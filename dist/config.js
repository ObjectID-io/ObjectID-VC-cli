import { getFullnodeUrl, IotaClient } from "@iota/iota-sdk/client";
function envStr(key, fallback) {
    const v = import.meta?.env?.[key];
    if (v === undefined || v === null || String(v).trim() === "")
        return fallback;
    return String(v);
}
function envBool(key, fallback = false) {
    const v = envStr(key);
    if (v === undefined)
        return fallback;
    return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}
function envNum(key, fallback) {
    const v = envStr(key);
    if (v === undefined)
        return fallback;
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
}
export const config = (network) => {
    const fullnodeUrl = getFullnodeUrl(network);
    const client = new IotaClient({ url: fullnodeUrl });
    const enable_object_menu = envBool("VITE_ENABLE_OBJECT_MENU", true);
    const enable_event_menu = envBool("VITE_ENABLE_EVENT_MENU", true);
    const enable_document_menu = envBool("VITE_ENABLE_DOCUMENT_MENU", true);
    const enable_identity_menu = envBool("VITE_ENABLE_IDENTITY_MENU", true);
    const splash_screen_message = envStr("VITE_SPALSH_SCREEN_MESSAGE", "");
    if (network == "testnet") {
        //testnet
        const document_packageID = "0x6e884a623d5661fca38cf9601cbc9fb85fa1d5aaff28a1fe96d260437b971ba7";
        const packageID = "0x79857c1738f31d70165149678ae051d5bffbaa26dbb66a25ad835e09f2180ae5";
        const policy = "0x4d83c5f05dae843dce44d5e793144679d1ff7512597e31606b54658d80c97458";
        const creditPackageID = "0x79857c1738f31d70165149678ae051d5bffbaa26dbb66a25ad835e09f2180ae5";
        const creditTreasuryCap = "0x1f3bfe6fb5e45520504dbb56e82dfabea90434079b9d9a3d7c18e4f5038dd17b";
        const creditTreasuryTokenType = "0x2::coin::TreasuryCap<" + creditPackageID + "::oid_credit::OID_CREDIT>";
        const officialPackages = [
            packageID,
            document_packageID,
            "0x868171cba737ee6d41e0e394b2d26f4670bfeb1d255ab747f61dd0e2f501d4b4",
        ];
        return {
            creditTokenType: "0x2::token::Token<" + packageID + "::oid_credit::OID_CREDIT>",
            OIDobjectType: packageID + "::oid_object::OIDObject",
            OIDDocumentType: document_packageID + "::oid_document::OIDDocument",
            policy,
            creditTreasuryCap,
            creditTreasuryTokenType,
            officialPackages,
            IOTAcontrolerCapTypes: [
                "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555::controller::ControllerCap",
            ],
            graphqlUrl: "https://graphql.testnet.iota.cafe",
            iotaExplorer: "https://explorer.iota.org",
            createOIDcontrollerCapURL: "https://api.objectid.io/api/create-OID-controllerCap",
            mintFreeCreditURL: "https://api.objectid.io/api/mint-free-credits",
            dlvcProxyUrl: "https://api.objectid.io/api/dlvc-proxy",
            gasStation: {
                gasStation1URL: "https://gas1.objectid.io",
                gasStation1Token: "1111",
                gasStation2URL: "https://gas2.objectid.io",
                gasStation2Token: "1111",
            },
            client,
            enable_object_menu,
            enable_event_menu,
            enable_document_menu,
            enable_identity_menu,
            splash_screen_message,
        };
    }
    else {
        //mainnet
        const document_packageID = "0x23ba3cf060ea3fbb53542e1a3347ee1eb215913081fecdf1eda462c3101da556";
        const packageID = "0xc6b77b8ab151fda5c98b544bda1f769e259146dc4388324e6737ecb9ab1a7465";
        const policy = "0xa10b50fb6e9b582eebb2b7b156a68c48489525f26022d6e877f63732292812af";
        const creditPackageID = "0xc6b77b8ab151fda5c98b544bda1f769e259146dc4388324e6737ecb9ab1a7465";
        const creditTreasuryCap = "0xf7044da6f62e67199038dc72b81eb2e581432c04e99180ec702dce763513b929";
        const creditTreasuryTokenType = "0x2::coin::TreasuryCap<" + creditPackageID + "::oid_credit::OID_CREDIT>";
        const officialPackages = [
            packageID,
            document_packageID,
            "0xfb3afd146f1b7b203b90d64df5fecf28f71aa102cc89598dc0dff268e0c81a42",
        ];
        return {
            creditTokenType: "0x2::token::Token<" + packageID + "::oid_credit::OID_CREDIT>",
            OIDobjectType: packageID + "::oid_object::OIDObject",
            OIDDocumentType: document_packageID + "::oid_document::OIDDocument",
            policy,
            creditTreasuryCap,
            creditTreasuryTokenType,
            officialPackages,
            IOTAcontrolerCapTypes: [
                "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08::controller::ControllerCap",
            ],
            graphqlUrl: "https://graphql.mainnet.iota.cafe",
            iotaExplorer: "https://explorer.iota.org",
            createOIDcontrollerCapURL: "https://api.objectid.io/api/create-OID-controllerCap",
            mintFreeCreditURL: "",
            dlvcProxyUrl: "https://api.objectid.io/api/dlvc-proxy",
            gasStation: {
                gasStation1URL: "https://m-gas1.objectid.io",
                gasStation1Token: "1111",
                gasStation2URL: "https://m-gas2.objectid.io",
                gasStation2Token: "1111",
            },
            client,
            enable_object_menu,
            enable_event_menu,
            enable_document_menu,
            enable_identity_menu,
            splash_screen_message,
        };
    }
};
