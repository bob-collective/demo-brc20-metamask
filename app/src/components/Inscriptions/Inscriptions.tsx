import {
  CTA,
  Card,
  Flex,
  Modal,
  ModalBody,
  ModalHeader,
  Table,
} from "@interlay/ui";
import { StyledWrapper } from "./Inscriptions.style";
import { useGetInscriptionIds } from "../../hooks/useGetInscriptionIds";
import { H2 } from "@interlay/ui";
import { useBtcSnap } from "../../hooks/useBtcSnap";
import { ReactNode, useState } from "react";
import { Inscription } from "./components/Inscription";
import { TransferOrdinalForm } from "./components/TransferOrdinal/TransferOrdinalForm";
import { useGetBalance } from "../../hooks/useGetBalance";

enum InscriptionsTableColumns {
  INSCRIPTION = "inscription",
  ACTIONS = "actions",
}

type InscriptionsTableRow = {
  id: string;
  [InscriptionsTableColumns.INSCRIPTION]: ReactNode;
  [InscriptionsTableColumns.ACTIONS]: ReactNode;
};

const Inscriptions = (): JSX.Element => {
  const [isInscriptionOpen, setIsInscriptionOpen] = useState(false);
  const [isTransferFormOpen, setIsTransferFormOpen] = useState(false);
  const [inscriptionId, setInscriptionId] = useState<string | undefined>();

  const { bitcoinAddress } = useBtcSnap();
  const { data: inscriptionIds } = useGetInscriptionIds(bitcoinAddress);

  const { data } = useGetBalance();
  console.log("useGetBalance data", data);

  const handleShowInscription = (id: string) => {
    setInscriptionId(id);
    setIsInscriptionOpen(true);
  };

  const handleShowTransferForm = (id: string) => {
    setInscriptionId(id);
    setIsTransferFormOpen(true);
  };

  const columns = [
    { name: "Inscription", id: InscriptionsTableColumns.INSCRIPTION },
    { name: "", id: InscriptionsTableColumns.ACTIONS },
  ];

  const inscriptionRows: InscriptionsTableRow[] = inscriptionIds
    ? inscriptionIds.map((id) => {
        return {
          id: id,
          inscription: `${id}`,
          actions: (
            <Flex justifyContent="flex-end" gap="spacing4" alignItems="center">
              <CTA onPress={() => handleShowInscription(id)} size="small">
                Show
              </CTA>
              <CTA onPress={() => handleShowTransferForm(id)} size="small">
                Transfer
              </CTA>
            </Flex>
          ),
        };
      })
    : [];

  return (
    <>
      <StyledWrapper direction="column" gap="spacing4">
        <H2>Ordinals portfolio</H2>
        <Card>
          <Table
            aria-label="Ordinals portfolio"
            columns={columns}
            rows={inscriptionRows}
          />
        </Card>
      </StyledWrapper>
      <Modal
        isOpen={isInscriptionOpen}
        onClose={() => setIsInscriptionOpen(false)}
      >
        <ModalHeader>{inscriptionId}</ModalHeader>
        <ModalBody>
          <Inscription id={inscriptionId} />
        </ModalBody>
      </Modal>
      <Modal
        isOpen={isTransferFormOpen}
        onClose={() => setIsTransferFormOpen(false)}
      >
        <ModalHeader>Transfer</ModalHeader>
        <ModalBody>
          <TransferOrdinalForm inscriptionId={inscriptionId || ""} />
        </ModalBody>
      </Modal>
    </>
  );
};

export default Inscriptions;
