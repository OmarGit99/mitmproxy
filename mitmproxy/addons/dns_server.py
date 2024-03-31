import asyncio
import socket
import ipaddress
from mitmproxy import ctx
from mitmproxy import dns
import dns.resolver as dnspython
from typing import Callable, Iterable, Union

class CustomDNSAddon:
    def __init__(self):
        self.custom_dns_server = ""  

    def load(self, loader):
        loader.add_option(
            name="dns_server",
            typespec=str,
            default="", 
            help="Custom DNS server to use for resolution"
        )

    def configure(self, updated):
        if "dns_server" in updated:
            self.custom_dns_server = ctx.options.dns_server

    async def resolve_question_by_name(
        self,
        question: dns.Question,
        loop: asyncio.AbstractEventLoop,
        family: socket.AddressFamily,
        ip: Callable[[str], Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
    ) -> Iterable[dns.ResourceRecord]:
        if self.custom_dns_server:
            try:
                resolver = dnspython.Resolver(configure=False)
                resolver.nameservers = [self.custom_dns_server]
                response = await loop.run_in_executor(None, resolver.query, question.name, question.type)
                print("dns server used")
                return map(
                    lambda record: dns.ResourceRecord(
                        name=question.name,
                        type=question.type,
                        class_=question.class_,
                        ttl=dns.ResourceRecord.DEFAULT_TTL,
                        data=ip(record.address).packed,
                    ),
                    response,
                )
            except dnspython.NXDOMAIN:
                raise dns.HostNotFound(question.name)
            except Exception as e:
                raise dns.DnsError(str(e))
        else:
            return await dns.resolve_question_by_name(question, loop, family, ip)

addons = [
    CustomDNSAddon()
]