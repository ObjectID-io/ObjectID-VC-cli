 node dist/issue-file-vc.js   --file "./test.txt"   --seed "1fc4a710291bafd0df16f590c48d76523bf842253fbee75bdc16c3a06fb13ffb"   --did-doc "./did.json" \  --out "./out"



node dist/verify-file-vc.js --file "./test.txt" --bundle "./out/test.txt.vc.bundle.json" --rpc "https://api.testnet.iota.cafe"