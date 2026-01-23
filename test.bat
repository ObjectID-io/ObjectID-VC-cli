 node dist/issue-file-vc.js   --file "./test.txt"   --seed "c3a3b693003156687604ee6e7d48dcabe568ec692b2ed0c83c4291ecd35780db"   --did-doc "./did.json" \  --out "./out"



node dist/verify-file-vc.js --file "./test.txt" --bundle "./out/test.txt.vc.bundle.json" --rpc "https://api.testnet.iota.cafe"