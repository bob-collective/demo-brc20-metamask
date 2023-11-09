// import truncateEthAddress from "truncate-eth-address";
// import Jazzicon, { jsNumberForAddress } from "react-jazzicon";
import { CTA, Flex } from "@interlay/ui";
// import { HTMLAttributes } from "react";
import "react-modern-drawer/dist/index.css";
import { Header } from "./Header";
import { StyledMain } from "./Layout.styles";
import { connect } from "../../utils/btcsnap-utils";
import { useState } from "react";

const Layout = ({ ...props }) => {
  const [isConnected, setIsConnected] = useState<boolean>();

  return (
    <>
      <CTA
        size="small"
        onPress={() => connect((connected) => setIsConnected(connected))}
      >
        {isConnected ? "Connected" : "Connect Metamask"}
        {/* {evmAccount ? (
          <Flex elementType="span" gap="spacing2">
            <Jazzicon diameter={20} seed={jsNumberForAddress(evmAccount)} />
            <Span style={{ color: "inherit" }} size="s" color="tertiary">
              {truncateEthAddress(evmAccount)} | bitcoin: {bitcoinAddress}
            </Span>
          </Flex>
        ) : (
          "Connect Wallet"
        )} */}
      </CTA>
      <Flex direction="column">
        <Header />
        <StyledMain direction="column" {...props} />
      </Flex>
    </>
  );
};

export { Layout };
