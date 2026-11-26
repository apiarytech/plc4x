/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Test peer only: an open62541 server with the address space internal/opcua's
 * Connection_server_test.go expects (the same one asyncua_server.py serves). Every security
 * policy open62541 has, anonymous login and the user operator/secret.
 *
 *   open62541_server <port> <certificate.der> <key.der>
 */

#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/pki_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile UA_Boolean running = true;

static void stopHandler(int sig) { running = false; }

static UA_ByteString loadFile(const char *path) {
    UA_ByteString content = UA_BYTESTRING_NULL;
    FILE *f = fopen(path, "rb");
    if(!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    content.length = (size_t)ftell(f);
    content.data = (UA_Byte *)UA_malloc(content.length);
    fseek(f, 0, SEEK_SET);
    if(fread(content.data, 1, content.length, f) != content.length) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(1);
    }
    fclose(f);
    return content;
}

static UA_UInt16 ns;

static void addFolder(UA_Server *server, const char *name) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
    UA_Server_addObjectNode(server, UA_NODEID_STRING(ns, (char *)name),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                            UA_QUALIFIEDNAME(ns, (char *)name),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE), attr, NULL, NULL);
}

static void addVariable(UA_Server *server, const char *id, const UA_DataType *type, void *value,
                        size_t arrayLength, UA_Boolean writable) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    const char *name = id + 5; /* after "Demo." */
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
    attr.dataType = type->typeId;
    UA_UInt32 dimensions[1] = {(UA_UInt32)arrayLength};
    if(arrayLength > 0) {
        UA_Variant_setArray(&attr.value, value, arrayLength, type);
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        attr.arrayDimensions = dimensions;
        attr.arrayDimensionsSize = 1;
    } else {
        UA_Variant_setScalar(&attr.value, value, type);
        attr.valueRank = UA_VALUERANK_SCALAR;
    }
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | (writable ? UA_ACCESSLEVELMASK_WRITE : 0);
    attr.userAccessLevel = attr.accessLevel;
    UA_StatusCode status = UA_Server_addVariableNode(
        server, UA_NODEID_STRING(ns, (char *)id), UA_NODEID_STRING(ns, "Demo"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(ns, (char *)name),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);
    if(status != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "cannot add %s: %s\n", id, UA_StatusCode_name(status));
        exit(1);
    }
}

static UA_Int32 counter = 0;

static void tick(UA_Server *server, void *data) {
    counter++;
    UA_Variant value;
    UA_Variant_setScalar(&value, &counter, &UA_TYPES[UA_TYPES_INT32]);
    UA_Server_writeValue(server, UA_NODEID_STRING(ns, "Demo.Counter"), value);
}

int main(int argc, char **argv) {
    if(argc != 4) {
        fprintf(stderr, "usage: %s <port> <certificate.der> <key.der>\n", argv[0]);
        return 2;
    }
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_ByteString certificate = loadFile(argv[2]);
    UA_ByteString key = loadFile(argv[3]);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_StatusCode status = UA_ServerConfig_setDefaultWithSecurityPolicies(
        config, (UA_UInt16)atoi(argv[1]), &certificate, &key, NULL, 0, NULL, 0, NULL, 0);
    if(status != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "cannot configure security: %s\n", UA_StatusCode_name(status));
        return 1;
    }
    /* Any client certificate: each test run generates a new one. */
    config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateVerification_AcceptAll(&config->secureChannelPKI);
    config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateVerification_AcceptAll(&config->sessionPKI);
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC("urn:plc4x:test:open62541");
    for(size_t i = 0; i < config->endpointsSize; i++) {
        UA_String_clear(&config->endpoints[i].server.applicationUri);
        UA_String_copy(&config->applicationDescription.applicationUri,
                       &config->endpoints[i].server.applicationUri);
    }

    /* Anonymous, and operator/secret. The password goes encrypted with the channel's policy, or
     * with Basic256Sha256 on a channel without one. */
    UA_UsernamePasswordLogin logins[1] = {{UA_STRING_STATIC("operator"), UA_STRING_STATIC("secret")}};
    UA_String tokenPolicy = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    config->accessControl.clear(&config->accessControl);
    status = UA_AccessControl_default(config, true, &tokenPolicy, 1, logins);
    if(status != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "cannot configure access control: %s\n", UA_StatusCode_name(status));
        return 1;
    }

    ns = UA_Server_addNamespace(server, "urn:plc4x:test");
    addFolder(server, "Demo");

    UA_Boolean b = true;
    UA_Int16 i16 = -1234;
    UA_Int32 i32 = 42;
    UA_Int64 i64 = -9000000000LL;
    UA_UInt32 u32 = 4000000000U;
    UA_Float f = 3.5f;
    UA_Double d = 2.718281828459045;
    UA_String s = UA_STRING("hello");
    UA_Int32 array[3] = {1, 2, 3};
    UA_Int32 readOnly = 7;
    UA_Int32 writableInt = 0;
    UA_Double writableDouble = 0;
    UA_Boolean writableBool = false;
    UA_String writableString = UA_STRING("");

    addVariable(server, "Demo.Bool", &UA_TYPES[UA_TYPES_BOOLEAN], &b, 0, false);
    addVariable(server, "Demo.Int16", &UA_TYPES[UA_TYPES_INT16], &i16, 0, false);
    addVariable(server, "Demo.Int32", &UA_TYPES[UA_TYPES_INT32], &i32, 0, false);
    addVariable(server, "Demo.Int64", &UA_TYPES[UA_TYPES_INT64], &i64, 0, false);
    addVariable(server, "Demo.UInt32", &UA_TYPES[UA_TYPES_UINT32], &u32, 0, false);
    addVariable(server, "Demo.Float", &UA_TYPES[UA_TYPES_FLOAT], &f, 0, false);
    addVariable(server, "Demo.Double", &UA_TYPES[UA_TYPES_DOUBLE], &d, 0, false);
    addVariable(server, "Demo.String", &UA_TYPES[UA_TYPES_STRING], &s, 0, false);
    addVariable(server, "Demo.Int32Array", &UA_TYPES[UA_TYPES_INT32], array, 3, false);
    addVariable(server, "Demo.Counter", &UA_TYPES[UA_TYPES_INT32], &counter, 0, false);
    addVariable(server, "Demo.ReadOnly", &UA_TYPES[UA_TYPES_INT32], &readOnly, 0, false);
    addVariable(server, "Demo.WritableInt32", &UA_TYPES[UA_TYPES_INT32], &writableInt, 0, true);
    addVariable(server, "Demo.WritableDouble", &UA_TYPES[UA_TYPES_DOUBLE], &writableDouble, 0, true);
    addVariable(server, "Demo.WritableBool", &UA_TYPES[UA_TYPES_BOOLEAN], &writableBool, 0, true);
    addVariable(server, "Demo.WritableString", &UA_TYPES[UA_TYPES_STRING], &writableString, 0, true);

    UA_Server_addRepeatedCallback(server, tick, NULL, 100, NULL);

    status = UA_Server_run(server, &running);
    UA_Server_delete(server);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&key);
    return status == UA_STATUSCODE_GOOD ? 0 : 1;
}
