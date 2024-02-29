# HashSpray-DC
A script that perform a Pre-Auth with a Domain Controller with a given username and a list of hashes 

#
Script still in development but works fine at this stage.

#
Didn't find that option 1 username and multiple hashes in both [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) and [Impacket](https://github.com/fortra/impacket) so thought could be useful to develop one.
Useful when retrieving multiple hashed from miscellaneous sources and whant to test them to pivot or lateral movement.

> [!IMPORTANT]
> The option has been merged in both crackmapexec (not supported anymore) and in [NXC](https://www.netexec.wiki/smb-protocol/password-spraying) that is the actively manteined successor.

---

> [!TIP]
> That script actually act differently from both previously mentioned solutions, since perform Kerberos Auth and in some restricted environment this actually bypass countermeasures of ban like [wail2ban](https://github.com/glasnt/wail2ban)
