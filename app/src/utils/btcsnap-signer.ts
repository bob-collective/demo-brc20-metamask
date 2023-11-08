import * as ecc from "@bitcoin-js/tiny-secp256k1-asmjs";
import * as retry from "async-retry";
import * as bitcoinjs from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import { address, Network, Psbt, Transaction } from "bitcoinjs-lib";
import { bitcoin, testnet } from "bitcoinjs-lib/src/networks";
import { RemoteSigner, inscribeText } from "@gobob/bob-sdk/dist/ordinals";
import { BitcoinNetwork, BitcoinScriptType, getExtendedPublicKey, getMasterFingerprint, getNetworkInSnap, signPsbt } from "./btcsnap-utils";
import { DefaultElectrsClient, ElectrsClient } from "@gobob/bob-sdk";
import { broadcastTx, getAddressUtxos, UTXO } from "./sdk-helpers";
import bs58check from "bs58check";
import coinSelect from "coinselect";
import { DefaultOrdinalsClient, InscriptionId, OrdinalsClient } from "./ordinals-client";

bitcoinjs.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

// TODO: revisit if we want to add config, or use script type dynamically
const hardcodedScriptType = BitcoinScriptType.P2WPKH;

async function getTxHex(txId: string) {
  return await retry(
    async (bail) => {
      // if anything throws, we retry
      const res = await fetch(
        `https://blockstream.info/testnet/api/tx/${txId}/hex`
      );

      if (res.status === 403) {
        // don't retry upon 403
        bail(new Error("Unauthorized"));
        throw "Unauthorized";
      } else if (res.status === 404) {
        throw "Could find tx";
      }

      return res.text();
    },
    {
      retries: 20,
      minTimeout: 2000,
      maxTimeout: 5000,
    }
  );
}

export function addressFromExtPubKey(xyzpub: string, bitcoinNetwork: BitcoinNetwork) {
  const network = bitcoinNetwork === BitcoinNetwork.Test ? testnet : bitcoin
  const forcedXpub = anyPubToXpub(xyzpub, network);
  const pubkey = bip32.fromBase58(forcedXpub, network).derive(0).derive(0).publicKey;
  return bitcoinjs.payments.p2wpkh({ pubkey, network }).address;
}

// force x/y/z/v pub key into xpub/tpub format
function anyPubToXpub(xyzpub: string, network: Network) {
  let data = bs58check.decode(xyzpub);
  data = data.subarray(4);

  // force to xpub/tpub format
  const tpubPrefix = "043587cf";
  const xpubPrefix = "0488b21e";
  const prefix = network === testnet ? tpubPrefix : xpubPrefix;

  data = Buffer.concat([Buffer.from(prefix, "hex"), data]);
  return bs58check.encode(data);
}

export class BtcSnapSigner implements RemoteSigner {
  async _getBtcSnapNetwork(): Promise<BitcoinNetwork> {
    return (await getNetworkInSnap()) === "test" ? BitcoinNetwork.Test : BitcoinNetwork.Main;
  }

  async getNetwork(): Promise<Network> {
    try {
      const network = await getNetworkInSnap();
      return network === "test" ? testnet : bitcoin;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async getPublicKey(): Promise<string> {
    const network = await this.getNetwork();
    const snapNetwork = network === bitcoin ? BitcoinNetwork.Main : BitcoinNetwork.Test;

    const extKey = await getExtendedPublicKey(snapNetwork, hardcodedScriptType);

    // extKey.xpub is a vpub with purpose and cointype (mainnet vs testnet) path embedded
    // convert to xpub/tpub before getting pubkey
    const forcedXpub = anyPubToXpub(extKey.xpub, network);

    // child is m/84'/1'/0'/0/0
    const pubkey = bip32.fromBase58(forcedXpub, network).derive(0).derive(0).publicKey;
    return pubkey.toString("hex");
  }

  async sendToAddress(toAddress: string, amount: number): Promise<string> {
    // TODO: this needs bob-sdk version that includes the changes from this PR: https://github.com/bob-collective/bob/pull/80
    // currently using copied methods
    const network = await this.getNetwork();
    const networkName = network === testnet ? "testnet" : "mainnet";
    const electrsClient = new DefaultElectrsClient(networkName);

    const senderPubKey = Buffer.from(await this.getPublicKey(), "hex");
    const senderAddress = bitcoinjs.payments.p2wpkh({ pubkey: senderPubKey, network }).address!;

    const txOutputs = [{
      address: toAddress,
      value: amount
    }];

    const utxos = await getAddressUtxos(electrsClient, senderAddress);

    const { inputs, outputs } = coinSelect(
      utxos.map(utxo => {
        return {
          txId: utxo.txid,
          vout: utxo.vout,
          value: utxo.value,
        }
      }),
      txOutputs,
      1 // fee rate
    );

    if (inputs === undefined) {
      throw Error("No inputs returned/selected by coinSelect");
    }

    if (outputs === undefined) {
      throw Error("No outputs returned/selected by coinSelect");
    }

    const psbt = new Psbt({ network });

    for (const input of inputs) {
      const txHex = await electrsClient.getTransactionHex(input.txId);
      const utx = Transaction.fromHex(txHex);

      const witnessUtxo = {
        script: utx.outs[input.vout].script,
        value: input.value,
      };
      const nonWitnessUtxo = utx.toBuffer()

      psbt.addInput({
        hash: input.txId,
        index: input.vout,
        nonWitnessUtxo,
        witnessUtxo,
        bip32Derivation: [
          {
            masterFingerprint: Buffer.from(await getMasterFingerprint() as any, "hex"),
            path: "m/84'/1'/0'/0/0",
            pubkey: senderPubKey,
          }
        ]
      });
    }

    const changeAddress = senderAddress;
    outputs.forEach(output => {
      // watch out, outputs may have been added that you need to provide
      // an output address/script for
      if (!output.address) {
        output.address = changeAddress;
      }

      psbt.addOutput({
        address: output.address,
        value: output.value,
      })
    });

    const snapNetwork = await this._getBtcSnapNetwork();
    const tx = await signPsbt(psbt.toBase64(), snapNetwork, hardcodedScriptType);

    return broadcastTx(electrsClient, tx.txHex);
  }

  async getUtxoIndex(toAddress: string, txId: string): Promise<number> {
    const txHex = await getTxHex(txId);
    const tx = Transaction.fromHex(txHex);
    const bitcoinNetwork = await this.getNetwork();
    const scriptPubKey = address.toOutputScript(toAddress, bitcoinNetwork);
    const utxoIndex = tx.outs.findIndex((out) =>
      out.script.equals(scriptPubKey)
    );
    return utxoIndex;
  }

  async signPsbt(_inputIndex: number, psbt: Psbt): Promise<Psbt> {
    // TODO: investigate if we can select input index in btcsnap
    const network = await this._getBtcSnapNetwork();
    const tx = await signPsbt(psbt.toBase64(), network, hardcodedScriptType);

    return Psbt.fromHex(tx.txHex);
  }
}

export async function createOrdinal(
  address: string,
  text: string
) {
  const signer = new BtcSnapSigner();
  // fee rate is 1 for testnet
  const tx = await inscribeText(signer, address, 1, text, 546);
  const res = await fetch('https://blockstream.info/testnet/api/tx', {
    method: 'POST',
    body: tx.toHex()
  });
  const txid = await res.text();
  return txid;
}

export async function sendInscription(address: string, inscriptionId: string): Promise<string> {
  const signer = new BtcSnapSigner();

  // fee rate is 1 for testnet
  const tx = await transferInscription(signer, address, inscriptionId, 1, 546);
  const res = await fetch('https://blockstream.info/testnet/api/tx', {
    method: 'POST',
    body: tx.toHex()
  });
  const txid = await res.text();
  return txid;
}

async function findUtxoForInscriptionId(
  electrsClient: ElectrsClient,
  ordinalsClient: OrdinalsClient,
  inscriptionId: InscriptionId,
  address: string
): Promise<UTXO> {
  // TODO: how can we find the UTXO using ordinalsClient?

  /**
   * Things inspected:
   * 1) The snippet below returns some data, but does not contain the outpoint - unless inscription id
   *    changes over time as it is transferred which I don't think it does.
   * 
   * const inscriptionUtxo = await ordinalsClient.getInscriptionFromId(inscriptionId as InscriptionId);
   * 
   * 2) Getting all utxo, and then looping through them using the snippet below. The problem is
   *    the InscriptionUTXO returned doesn't seem to contain the inscription id, only the data
   * 
   * const inscriptionUtxo = await ordinalsClient.getInscriptionFromUTXO(utxo.txid);
   * 
   * 3) ??? some other way I haven't thought of yet
   * 
   */

  throw Error("not implemented yet");
  
}

/**
 * Returns a given address' utxos that don't contain any inscriptions.
 */
async function getSafeUtxos(
  electrsClient: ElectrsClient,
  ordinalsClient: OrdinalsClient,
  address: string
): Promise<UTXO[]> {
  // step 1: get all utxos for the address
  const utxos = await getAddressUtxos(electrsClient, address);

  const safeUtxos = [];
  for (const utxo of utxos) {
    // optimize this later
    const inscriptionUtxo = await ordinalsClient.getInscriptionFromUTXO(utxo.txid);
    if (inscriptionUtxo.inscriptions.length === 0) {
      safeUtxos.push(utxo);
    }
  }

  return safeUtxos;
}

async function transferInscription(
  signer: BtcSnapSigner,
  toAddress: string,
  inscriptionId: string,
  feeRate: number = 1,
): Promise<Transaction> {
  if ( inscriptionId.length !== 64) {
    throw Error(`Inscription ID has unexpected length: ${inscriptionId.length} (expected: 64)`);
  }

  const network = await signer.getNetwork();
  const pubkey = Buffer.from(await signer.getPublicKey(), "hex");
  const fromAddress = bitcoinjs.payments.p2wpkh({ pubkey, network }).address!;

  const networkName = network === testnet ? "testnet" : "mainnet";
  const ordinalsClient = new DefaultOrdinalsClient(networkName);
  const electrsClient = new DefaultElectrsClient(networkName);
  
  const inscriptionUtxo = await findUtxoForInscriptionId(electrsClient, ordinalsClient, inscriptionId as InscriptionId, fromAddress);

  // prepare single input
  const txInputs = [{
    txId: inscriptionUtxo.txid,
    vout: inscriptionUtxo.vout,
    value: inscriptionUtxo.value
  }];

  // TODO: review output values
  const txOutputs = [{
    address: toAddress,
    value: 1
  }];

  const { inputs, outputs } = coinSelect(txInputs, txOutputs, feeRate);

  if (inputs === undefined) {
    throw Error("No inputs returned/selected by coinSelect");
  }

  if (outputs === undefined) {
    throw Error("No outputs returned/selected by coinSelect");
  }

  const psbt = new Psbt({ network });

  throw Error("Implementation incomplete");

  // TODO: continue here
  // construct psbt inputs
  // construct outputs containing inscription? (not sure how to)
  // send psbt to RemoteSigner for signature
  // return signed psbt


  // TODO: snippet can be useful if we need to add more inputs to cover fees
  // const safeUtxos = await getSafeUtxos(electrsClient, ordinalsClient, fromAddress);
  // // sort smallest to largest before adding in some
  // safeUtxos.sort((a , b) => a.value - b.value);

}