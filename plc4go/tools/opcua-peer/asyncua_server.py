# Licensed to the Apache Software Foundation (ASF) under one or more contributor license
# agreements. See the NOTICE file distributed with this work for additional information regarding
# copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License. You may obtain a
# copy of the License at https://www.apache.org/licenses/LICENSE-2.0. Unless required by
# applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# Test peer only: an asyncua (FreeOpcUa, Python) server with the address space internal/opcua's
# Connection_server_test.go expects, the same one open62541_server.c serves.
#
#   python3 asyncua_server.py <port> <certificate.der> <key.pem>
import asyncio
import sys

from asyncua import Server, ua
from asyncua.crypto.permission_rules import PermissionRuleset, User, UserRole
from asyncua.server.user_managers import UserManager


class Users(UserManager):
    """Anonymous logins and operator/secret."""

    def get_user(self, iserver, username=None, password=None, certificate=None):
        if not username:
            return User(role=UserRole.Anonymous)
        if username == "operator" and password == "secret":
            return User(role=UserRole.User, name=username)
        return None


class Rules(PermissionRuleset):
    """Anonymous users may do everything but write; operator may write too."""

    def check_validity(self, user, action_type_id, body):
        if user.role == UserRole.Anonymous:
            return action_type_id != ua.NodeId(ua.ObjectIds.WriteRequest_Encoding_DefaultBinary)
        return True


async def main():
    port, certificate, key = sys.argv[1], sys.argv[2], sys.argv[3]
    server = Server(user_manager=Users())
    await server.init()
    server.set_endpoint(f"opc.tcp://0.0.0.0:{port}/")
    server.set_server_name("plc4x test asyncua")
    await server.set_application_uri("urn:plc4x:test:asyncua")
    server.set_security_policy(
        [
            ua.SecurityPolicyType.NoSecurity,
            ua.SecurityPolicyType.Basic256Sha256_Sign,
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
            ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
        ],
        permission_ruleset=Rules(),
    )
    server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
    await server.load_certificate(certificate)
    await server.load_private_key(key)

    ns = await server.register_namespace("urn:plc4x:test")
    demo = await server.nodes.objects.add_folder(ua.NodeId("Demo", ns), ua.QualifiedName("Demo", ns))

    async def variable(name, value, variant_type, writable=False):
        node = await demo.add_variable(
            ua.NodeId("Demo." + name, ns), ua.QualifiedName(name, ns), ua.Variant(value, variant_type)
        )
        if writable:
            await node.set_writable()
        return node

    V = ua.VariantType
    await variable("Bool", True, V.Boolean)
    await variable("Int16", -1234, V.Int16)
    await variable("Int32", 42, V.Int32)
    await variable("Int64", -9000000000, V.Int64)
    await variable("UInt32", 4000000000, V.UInt32)
    await variable("Float", 3.5, V.Float)
    await variable("Double", 2.718281828459045, V.Double)
    await variable("String", "hello", V.String)
    array = await variable("Int32Array", [1, 2, 3], V.Int32)
    await array.write_value_rank(ua.ValueRank.OneDimension)
    await array.write_array_dimensions([3])
    counter = await variable("Counter", 0, V.Int32)
    await variable("ReadOnly", 7, V.Int32)
    await variable("WritableInt32", 0, V.Int32, writable=True)
    await variable("WritableDouble", 0.0, V.Double, writable=True)
    await variable("WritableBool", False, V.Boolean, writable=True)
    await variable("WritableString", "", V.String, writable=True)

    async with server:
        print("asyncua server running", flush=True)
        count = 0
        while True:
            await asyncio.sleep(0.1)
            count += 1
            await counter.write_value(ua.Variant(count, V.Int32))


if __name__ == "__main__":
    asyncio.run(main())
