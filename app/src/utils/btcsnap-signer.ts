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
    const ordinalsClient = new DefaultOrdinalsClient(networkName);

    const senderPubKey = Buffer.from(await this.getPublicKey(), "hex");
    const senderAddress = bitcoinjs.payments.p2wpkh({ pubkey: senderPubKey, network }).address!;

    const txOutputs = [{
      address: toAddress,
      value: amount
    }];

    const allUtxos = await getAddressUtxos(electrsClient, senderAddress);
    const utxos = await findSafeUtxos(ordinalsClient, allUtxos);

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
    const masterFingerprint = Buffer.from(await getMasterFingerprint() as any, "hex");
    // TODO: clean up magic paths
    const derivationPath = "m/84'/1'/0'/0/0";

    for (const input of inputs) {
      await addPsbtInput(electrsClient, psbt, input, senderPubKey, masterFingerprint, derivationPath);
    }

    const changeAddress = senderAddress;
    outputs.forEach(output => {
      addPsbtOutput(psbt, output, changeAddress);
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

async function addPsbtInput(
  electrsClient: ElectrsClient,
  psbt: Psbt,
  input: {txId: string, vout: number, value: number},
  senderPubKey: Buffer,
  masterFingerprint: Buffer,
  derivationPath: string

): Promise<Psbt> {
  const txHex = await electrsClient.getTransactionHex(input.txId);
  const utx = Transaction.fromHex(txHex);

  const witnessUtxo = {
    script: utx.outs[input.vout].script,
    value: input.value,
  };
  const nonWitnessUtxo = utx.toBuffer();

  return psbt.addInput({
    hash: input.txId,
    index: input.vout,
    nonWitnessUtxo,
    witnessUtxo,
    bip32Derivation: [
      {
        masterFingerprint,
        path: derivationPath,
        pubkey: senderPubKey,
      }
    ]
  });
}

// change address is only added when coinselect outputs have empty addresses
function addPsbtOutput(
  psbt: Psbt,
  output: { address?: string, value: number },
  changeAddress: string
): Psbt {
  // watch out, outputs may have been added that you need to provide
  // an output address/script for
  if (!output.address) {
    output.address = changeAddress;
  }

  return psbt.addOutput({
    address: output.address,
    value: output.value,
  })
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
  const txid = await transferInscription(signer, address, inscriptionId, 1);
  return txid;
}

async function findUtxoForInscriptionId(
  ordinalsClient: OrdinalsClient,
  utxos: UTXO[],
  inscriptionId: InscriptionId
): Promise<UTXO | undefined> {
  for (const utxo of utxos) {
    const inscrUtxo =  await ordinalsClient.getInscriptionFromUTXO(utxo.txid);
    if ( inscrUtxo.inscriptions && inscrUtxo.inscriptions.includes(inscriptionId) ) {
      return utxo;
    }
  }

  return undefined;
}

/**
 * Returns only the utxos that don't contain any inscriptions.
 */
async function findSafeUtxos(
  ordinalsClient: OrdinalsClient,
  utxos: UTXO[]
): Promise<UTXO[]> {
  const safeUtxos = [];
  for (const utxo of utxos) {
    // can be optimized later
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
): Promise<string> {
  if ( inscriptionId.length !== 64) {
    throw Error(`Inscription ID has unexpected length: ${inscriptionId.length} (expected: 64)`);
  }

  const network = await signer.getNetwork();
  const pubkey = Buffer.from(await signer.getPublicKey(), "hex");
  const fromAddress = bitcoinjs.payments.p2wpkh({ pubkey, network }).address!;

  const networkName = network === testnet ? "testnet" : "mainnet";
  const ordinalsClient = new DefaultOrdinalsClient(networkName);
  const electrsClient = new DefaultElectrsClient(networkName);

  const utxos = await getAddressUtxos(electrsClient, fromAddress);
  const inscriptionUtxo = await findUtxoForInscriptionId(ordinalsClient, utxos, inscriptionId as InscriptionId);

  if (inscriptionUtxo === undefined) {
    throw Error(`Unable to find utxo owned by address [${fromAddress}] containing inscription id [${inscriptionId}]`);
  }

  // prepare single input
  const txInputs = [{
    txId: inscriptionUtxo.txid,
    vout: inscriptionUtxo.vout,
    value: inscriptionUtxo.value
  }];

  // TODO: review output values, eg. is one sat enough?
  const txOutputs = [{
    address: toAddress,
    value: 1
  }];

  const { inputs, outputs } = coinSelect(txInputs, txOutputs, feeRate);

  // TODO: Might need to add more inputs for fees if utxo is not enough, something like this:
  // const safeUtxos = await findSafeUtxos(ordinalsClient, utxos, fromAddress);
  // // sort smallest to largest before adding in some
  // safeUtxos.sort((a , b) => a.value - b.value);
  // // pick best fit(s) and do coinselect again.

  if (inputs === undefined) {
    throw Error("No inputs returned/selected by coinSelect");
  }

  if (outputs === undefined) {
    throw Error("No outputs returned/selected by coinSelect");
  }

  const psbt = new Psbt({ network });

  const masterFingerprint = Buffer.from(await getMasterFingerprint() as any, "hex");
  // TODO: clean up magic paths
  const derivationPath = "m/84'/1'/0'/0/0";
  for (const input of inputs) {
    await addPsbtInput(electrsClient, psbt, input, pubkey, masterFingerprint, derivationPath);
  }

  const changeAddress = fromAddress;
  outputs.forEach((output) => {
    addPsbtOutput(psbt, output, changeAddress);
  });

  const snapNetwork = network === bitcoin ? BitcoinNetwork.Main : BitcoinNetwork.Test;
  const tx = await signPsbt(psbt.toBase64(), snapNetwork, hardcodedScriptType);

  return broadcastTx(electrsClient, tx.txHex);
}