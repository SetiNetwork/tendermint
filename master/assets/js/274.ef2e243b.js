(window.webpackJsonp=window.webpackJsonp||[]).push([[274],{848:function(e,t,a){"use strict";a.r(t);var n=a(1),o=Object(n.a)({},(function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("ContentSlotsDistributor",{attrs:{"slot-key":e.$parent.slotKey}},[a("h1",{attrs:{id:"terraform-ansible"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#terraform-ansible"}},[e._v("#")]),e._v(" Terraform & Ansible")]),e._v(" "),a("blockquote",[a("p",[e._v("Note: These commands/files are not being maintained by the tendermint team currently. Please use them carefully.")])]),e._v(" "),a("p",[e._v("Automated deployments are done using\n"),a("a",{attrs:{href:"https://www.terraform.io/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Terraform"),a("OutboundLink")],1),e._v(" to create servers on Digital\nOcean then "),a("a",{attrs:{href:"http://www.ansible.com/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Ansible"),a("OutboundLink")],1),e._v(" to create and manage\ntestnets on those servers.")]),e._v(" "),a("h2",{attrs:{id:"install"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#install"}},[e._v("#")]),e._v(" Install")]),e._v(" "),a("p",[e._v("NOTE: see the "),a("a",{attrs:{href:"https://github.com/tendermint/tendermint/blob/master/networks/remote/integration.sh",target:"_blank",rel:"noopener noreferrer"}},[e._v("integration bash\nscript"),a("OutboundLink")],1),e._v("\nthat can be run on a fresh DO droplet and will automatically spin up a 4\nnode testnet. The script more or less does everything described below.")]),e._v(" "),a("ul",[a("li",[e._v("Install "),a("a",{attrs:{href:"https://www.terraform.io/downloads.html",target:"_blank",rel:"noopener noreferrer"}},[e._v("Terraform"),a("OutboundLink")],1),e._v(" and\n"),a("a",{attrs:{href:"http://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html",target:"_blank",rel:"noopener noreferrer"}},[e._v("Ansible"),a("OutboundLink")],1),e._v("\non a Linux machine.")]),e._v(" "),a("li",[e._v("Create a "),a("a",{attrs:{href:"https://cloud.digitalocean.com/settings/api/tokens",target:"_blank",rel:"noopener noreferrer"}},[e._v("DigitalOcean API\ntoken"),a("OutboundLink")],1),e._v(" with read\nand write capability.")]),e._v(" "),a("li",[e._v("Install the python dopy package ("),a("code",[e._v("pip install dopy")]),e._v(")")]),e._v(" "),a("li",[e._v("Create SSH keys ("),a("code",[e._v("ssh-keygen")]),e._v(")")]),e._v(" "),a("li",[e._v("Set environment variables:")])]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"ZXhwb3J0IERPX0FQSV9UT0tFTj0mcXVvdDthYmNkZWYwMTIzNDU2Nzg5MGFiY2RlZjAxMjM0NTY3ODkwJnF1b3Q7CmV4cG9ydCBTU0hfS0VZX0ZJTEU9JnF1b3Q7JEhPTUUvLnNzaC9pZF9yc2EucHViJnF1b3Q7Cg=="}}),e._v(" "),a("p",[e._v("These will be used by both "),a("code",[e._v("terraform")]),e._v(" and "),a("code",[e._v("ansible")]),e._v(".")]),e._v(" "),a("h2",{attrs:{id:"terraform"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#terraform"}},[e._v("#")]),e._v(" Terraform")]),e._v(" "),a("p",[e._v("This step will create four Digital Ocean droplets. First, go to the\ncorrect directory:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"Y2QgJEdPUEFUSC9zcmMvZ2l0aHViLmNvbS90ZW5kZXJtaW50L3RlbmRlcm1pbnQvbmV0d29ya3MvcmVtb3RlL3RlcnJhZm9ybQo="}}),e._v(" "),a("p",[e._v("then:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"dGVycmFmb3JtIGluaXQKdGVycmFmb3JtIGFwcGx5IC12YXIgRE9fQVBJX1RPS0VOPSZxdW90OyRET19BUElfVE9LRU4mcXVvdDsgLXZhciBTU0hfS0VZX0ZJTEU9JnF1b3Q7JFNTSF9LRVlfRklMRSZxdW90Owo="}}),e._v(" "),a("p",[e._v("and you will get a list of IP addresses that belong to your droplets.")]),e._v(" "),a("p",[e._v("With the droplets created and running, let's setup Ansible.")]),e._v(" "),a("h2",{attrs:{id:"ansible"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#ansible"}},[e._v("#")]),e._v(" Ansible")]),e._v(" "),a("p",[e._v("The playbooks in "),a("a",{attrs:{href:"https://github.com/tendermint/tendermint/tree/master/networks/remote/ansible",target:"_blank",rel:"noopener noreferrer"}},[e._v("the ansible\ndirectory"),a("OutboundLink")],1),e._v("\nrun ansible roles to configure the sentry node architecture. You must\nswitch to this directory to run ansible\n("),a("code",[e._v("cd $GOPATH/src/github.com/tendermint/tendermint/networks/remote/ansible")]),e._v(").")]),e._v(" "),a("p",[e._v("There are several roles that are self-explanatory:")]),e._v(" "),a("p",[e._v("First, we configure our droplets by specifying the paths for tendermint\n("),a("code",[e._v("BINARY")]),e._v(") and the node files ("),a("code",[e._v("CONFIGDIR")]),e._v("). The latter expects any\nnumber of directories named "),a("code",[e._v("node0, node1, ...")]),e._v(" and so on (equal to the\nnumber of droplets created).")]),e._v(" "),a("p",[e._v("To create the node files run:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"dGVuZGVybWludCB0ZXN0bmV0Cg=="}}),e._v(" "),a("p",[e._v("Then, to configure our droplets run:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"YW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgY29uZmlnLnltbCAtZSBCSU5BUlk9JEdPUEFUSC9zcmMvZ2l0aHViLmNvbS90ZW5kZXJtaW50L3RlbmRlcm1pbnQvYnVpbGQvdGVuZGVybWludCAtZSBDT05GSUdESVI9JEdPUEFUSC9zcmMvZ2l0aHViLmNvbS90ZW5kZXJtaW50L3RlbmRlcm1pbnQvbmV0d29ya3MvcmVtb3RlL2Fuc2libGUvbXl0ZXN0bmV0Cg=="}}),e._v(" "),a("p",[e._v("Voila! All your droplets now have the "),a("code",[e._v("tendermint")]),e._v(" binary and required\nconfiguration files to run a testnet.")]),e._v(" "),a("p",[e._v("Next, we run the install role:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"YW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgaW5zdGFsbC55bWwK"}}),e._v(" "),a("p",[e._v("which as you'll see below, executes\n"),a("code",[e._v("tendermint node --proxy-app=kvstore")]),e._v(" on all droplets. Although we'll\nsoon be modifying this role and running it again, this first execution\nallows us to get each "),a("code",[e._v("node_info.id")]),e._v(" that corresponds to each\n"),a("code",[e._v("node_info.listen_addr")]),e._v(". (This part will be automated in the future). In\nyour browser (or using "),a("code",[e._v("curl")]),e._v("), for every droplet, go to IP:26657/status\nand note the two just mentioned "),a("code",[e._v("node_info")]),e._v(" fields. Notice that blocks\naren't being created ("),a("code",[e._v("latest_block_height")]),e._v(" should be zero and not\nincreasing).")]),e._v(" "),a("p",[e._v("Next, open "),a("code",[e._v("roles/install/templates/systemd.service.j2")]),e._v(" and look for the\nline "),a("code",[e._v("ExecStart")]),e._v(" which should look something like:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"RXhlY1N0YXJ0PS91c3IvYmluL3RlbmRlcm1pbnQgbm9kZSAtLXByb3h5LWFwcD1rdnN0b3JlCg=="}}),e._v(" "),a("p",[e._v("and add the "),a("code",[e._v("--p2p.persistent-peers")]),e._v(" flag with the relevant information\nfor each node. The resulting file should look something like:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"W1VuaXRdCkRlc2NyaXB0aW9uPXt7c2VydmljZX19ClJlcXVpcmVzPW5ldHdvcmstb25saW5lLnRhcmdldApBZnRlcj1uZXR3b3JrLW9ubGluZS50YXJnZXQKCltTZXJ2aWNlXQpSZXN0YXJ0PW9uLWZhaWx1cmUKVXNlcj17e3NlcnZpY2V9fQpHcm91cD17e3NlcnZpY2V9fQpQZXJtaXNzaW9uc1N0YXJ0T25seT10cnVlCkV4ZWNTdGFydD0vdXNyL2Jpbi90ZW5kZXJtaW50IG5vZGUgLS1wcm94eS1hcHA9a3ZzdG9yZSAtLXAycC5wZXJzaXN0ZW50LXBlZXJzPTE2N2I4MDI0MmMzMDBiZjBjY2ZiM2NlZDNkZWM2MGRjMmE4MTc3NmVAMTY1LjIyNy40MS4yMDY6MjY2NTYsM2M3YTU5MjA4MTE1NTBjMDRiZjdhMGIyZjFlMDJhYjUyMzE3YjVlNkAxNjUuMjI3LjQzLjE0NjoyNjY1NiwzMDNhMWE0MzEyYzMwNTI1Yzk5YmE2NjUyMmRkODFjY2E1NmEzNjFhQDE1OS44OS4xMTUuMzI6MjY2NTYsYjY4NmMyYTdmNGIxYjQ2ZGNhOTZhZjNhMGYzMWE2YTdiZWFlMGJlNEAxNTkuODkuMTE5LjEyNToyNjY1NgpFeGVjUmVsb2FkPS9iaW4va2lsbCAtSFVQICRNQUlOUElECktpbGxTaWduYWw9U0lHVEVSTQoKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg=="}}),e._v(" "),a("p",[e._v("Then, stop the nodes:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"YW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgc3RvcC55bWwK"}}),e._v(" "),a("p",[e._v("Finally, we run the install role again:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"YW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgaW5zdGFsbC55bWwK"}}),e._v(" "),a("p",[e._v("to re-run "),a("code",[e._v("tendermint node")]),e._v(" with the new flag, on all droplets. The\n"),a("code",[e._v("latest_block_hash")]),e._v(" should now be changing and "),a("code",[e._v("latest_block_height")]),e._v("\nincreasing. Your testnet is now up and running 😃")]),e._v(" "),a("p",[e._v("Peek at the logs with the status role:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"YW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgc3RhdHVzLnltbAo="}}),e._v(" "),a("h2",{attrs:{id:"logging"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#logging"}},[e._v("#")]),e._v(" Logging")]),e._v(" "),a("p",[e._v("The crudest way is the status role described above. You can also ship\nlogs to Logz.io, an Elastic stack (Elastic search, Logstash and Kibana)\nservice provider. You can set up your nodes to log there automatically.\nCreate an account and get your API key from the notes on "),a("a",{attrs:{href:"https://app.logz.io/#/dashboard/data-sources/Filebeat",target:"_blank",rel:"noopener noreferrer"}},[e._v("this\npage"),a("OutboundLink")],1),e._v(", then:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"eXVtIGluc3RhbGwgc3lzdGVtZC1kZXZlbCB8fCBlY2hvICZxdW90O1RoaXMgd2lsbCBvbmx5IHdvcmsgb24gUkhFTC1iYXNlZCBzeXN0ZW1zLiZxdW90OwphcHQtZ2V0IGluc3RhbGwgbGlic3lzdGVtZC1kZXYgfHwgZWNobyAmcXVvdDtUaGlzIHdpbGwgb25seSB3b3JrIG9uIERlYmlhbi1iYXNlZCBzeXN0ZW1zLiZxdW90OwoKZ28gaW5zdGFsbCBnaXRodWIuY29tL21oZWVzZS9qb3VybmFsYmVhdEBsYXRlc3QKYW5zaWJsZS1wbGF5Ym9vayAtaSBpbnZlbnRvcnkvZGlnaXRhbF9vY2Vhbi5weSAtbCBzZW50cnluZXQgbG9nemlvLnltbCAtZSBMT0daSU9fVE9LRU49QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDUK"}}),e._v(" "),a("h2",{attrs:{id:"cleanup"}},[a("a",{staticClass:"header-anchor",attrs:{href:"#cleanup"}},[e._v("#")]),e._v(" Cleanup")]),e._v(" "),a("p",[e._v("To remove your droplets, run:")]),e._v(" "),a("tm-code-block",{staticClass:"codeblock",attrs:{language:"sh",base64:"dGVycmFmb3JtIGRlc3Ryb3kgLXZhciBET19BUElfVE9LRU49JnF1b3Q7JERPX0FQSV9UT0tFTiZxdW90OyAtdmFyIFNTSF9LRVlfRklMRT0mcXVvdDskU1NIX0tFWV9GSUxFJnF1b3Q7Cg=="}})],1)}),[],!1,null,null,null);t.default=o.exports}}]);