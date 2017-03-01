/*
 * Copyright (C) 2009 The Android Open Source Project
 * Modifications Copyright (C) 2011-2017 TheCTO Technological Entrepreneurship & Consulting LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <keystore/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <keystore/keystore.h>
#include <sys/un.h>
#include <openssl/evp.h>

using namespace android;

static const char* responses[] = {
    NULL,
    /* [NO_ERROR]           = */ "No error",
    /* [LOCKED]             = */ "Locked",
    /* [UNINITIALIZED]      = */ "Uninitialized",
    /* [SYSTEM_ERROR]       = */ "System error",
    /* [PROTOCOL_ERROR]     = */ "Protocol error",
    /* [PERMISSION_DENIED]  = */ "Permission denied",
    /* [KEY_NOT_FOUND]      = */ "Key not found",
    /* [VALUE_CORRUPTED]    = */ "Value corrupted",
    /* [UNDEFINED_ACTION]   = */ "Undefined action",
    /* [WRONG_PASSWORD]     = */ "Wrong password (last chance)",
    /* [WRONG_PASSWORD + 1] = */ "Wrong password (2 tries left)",
    /* [WRONG_PASSWORD + 2] = */ "Wrong password (3 tries left)",
    /* [WRONG_PASSWORD + 3] = */ "Wrong password (4 tries left)",
};

#define NO_ARG_INT_RETURN(cmd) \
    do { \
        if (strcmp(argv[1], #cmd) == 0) { \
            int32_t ret = service->cmd(); \
            if (ret < 0) { \
                fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret); \
                return 1; \
            } else { \
                printf(#cmd ": %s (%d)\n", responses[ret], ret); \
                return 0; \
            } \
        } \
    } while (0)

#define SINGLE_ARG_INT_RETURN(cmd) \
    do { \
        if (strcmp(argv[1], #cmd) == 0) { \
            if (argc < 3) { \
                fprintf(stderr, "Usage: %s " #cmd " <name>\n", argv[0]); \
                return 1; \
            } \
            int32_t ret = service->cmd(String16(argv[2])); \
            if (ret < 0) { \
                fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret); \
                return 1; \
            } else { \
                printf(#cmd ": %s (%d)\n", responses[ret], ret); \
                return 0; \
            } \
        } \
    } while (0)

#define SINGLE_ARG_PLUS_UID_INT_RETURN(cmd) \
    do { \
        if (strcmp(argv[1], #cmd) == 0) { \
            if (argc < 3) { \
                fprintf(stderr, "Usage: %s " #cmd " <name> <uid>\n", argv[0]); \
                return 1; \
            } \
            int uid = -1; \
            if (argc > 3) { \
                uid = atoi(argv[3]); \
                fprintf(stderr, "Running as uid %d\n", uid); \
            } \
            int32_t ret = service->cmd(String16(argv[2]), uid); \
            if (ret < 0) { \
                fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret); \
                return 1; \
            } else { \
                printf(#cmd ": %s (%d)\n", responses[ret], ret); \
                return 0; \
            } \
        } \
    } while (0)

#define STING_ARG_DATA_STDIN_INT_RETURN(cmd) \
    do { \
        if (strcmp(argv[1], #cmd) == 0) { \
            if (argc < 3) { \
                fprintf(stderr, "Usage: %s " #cmd " <name>\n", argv[0]); \
                return 1; \
            } \
            uint8_t* data; \
            size_t dataSize; \
            read_input(&data, &dataSize); \
            int32_t ret = service->cmd(String16(argv[2]), data, dataSize); \
            if (ret < 0) { \
                fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret); \
                return 1; \
            } else { \
                printf(#cmd ": %s (%d)\n", responses[ret], ret); \
                return 0; \
            } \
        } \
    } while (0)

#define SINGLE_ARG_DATA_RETURN(cmd) \
    do { \
        if (strcmp(argv[1], #cmd) == 0) { \
            if (argc < 3) { \
                fprintf(stderr, "Usage: %s " #cmd " <name>\n", argv[0]); \
                return 1; \
            } \
            uint8_t* data; \
            size_t dataSize; \
            int32_t ret = service->cmd(String16(argv[2]), &data, &dataSize); \
            if (ret < 0) { \
                fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret); \
                return 1; \
            } else if (ret != ::NO_ERROR) { \
                fprintf(stderr, "%s: " #cmd ": %s (%d)\n", argv[0], responses[ret], ret); \
                return 1; \
            } else { \
                fwrite(data, dataSize, 1, stdout); \
                fflush(stdout); \
                free(data); \
                return 0; \
            } \
        } \
    } while (0)


#define SPECIAL_KEY_ALIAS "USRPKEY_5asf6fd589fkljdsdgker45dfsncb4jkcjwejv5jk"

static int saw(sp<IKeystoreService> service, const String16& name, int uid) {
    Vector<String16> matches;
    int32_t ret = service->saw(name, uid, &matches);
    if (ret < 0) {
        fprintf(stderr, "saw: could not connect: %d\n", ret);
        return 1;
    } else if (ret != ::NO_ERROR) {
        fprintf(stderr, "saw: %s (%d)\n", responses[ret], ret);
        return 1;
    } else {
        Vector<String16>::const_iterator it = matches.begin();
        for (; it != matches.end(); ++it) {
            printf("%s\n", String8(*it).string());
        }
        return 0;
    }
}

static int32_t exist(sp<IKeystoreService> service, const String16& name) {
	int32_t ret = service->exist(name, -1);

	if (ret < 0) {
		fprintf(stderr, "exist: could not connect: %d\n", ret);
	}
	return ret;
}

static int create_address(const char* name, struct sockaddr_un* pAddr, socklen_t* pSockLen)
{

    int nameLen = strlen(name);
    if (nameLen >= (int) sizeof(pAddr->sun_path) -1)  /* too long? */
        return -1;
    pAddr->sun_path[0] = '\0';  /* abstract namespace */
    strcpy(pAddr->sun_path+1, name);
    pAddr->sun_family = AF_LOCAL;
    *pSockLen = 1 + nameLen + offsetof(struct sockaddr_un, sun_path);
    return 0;
}

static int get_key_from_server(pid_t pid, uid_t user, int action, const unsigned char * from_key, size_t from_key_size, unsigned char * to_key, size_t expected_to_size,ssize_t * recv_bytes) {
	int rc = 0;
    struct sockaddr_un sockAddr;
    socklen_t sockLen;
    //char address[30] = {0};
    char address[30] = "encrypt_1000_2372";
    struct ucred credentials;
    //sprintf(address,"encrypt_%d_%d", user, pid);

    ALOGD("IDODOD - trying to connect to <%s>\n", address);
	rc = create_address(address, &sockAddr, &sockLen);
	if (rc >= 0) {
		int fd = socket(AF_LOCAL, SOCK_STREAM, 0);
		if (fd >= 0) {
			rc = connect(fd, (const struct sockaddr*) &sockAddr, sockLen);
			if (rc >= 0) {
				socklen_t len = sizeof(struct ucred);
				rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len);
				if (rc >= 0) {
					ALOGD("IDODOD - The remote socket uid is <%d>\n", credentials.uid);
					if (credentials.uid == user) {
						unsigned char * message = (unsigned char *)malloc(sizeof(unsigned char)*(from_key_size+1));
						if (message) {
							message[0] = action;
							memcpy(message+1,from_key, from_key_size);
							int bytes_sent = send(fd, message, from_key_size+1,0);
							free(message);
							if (bytes_sent) {
								ssize_t nread = read(fd, to_key, expected_to_size);
								 if (nread == -1 || nread == 0) {
									 rc = -1;
									 ALOGE("IDODOD - %s", strerror(errno));
								 } else {
									 rc = 0;
									 *recv_bytes = nread;
								 }
							} else {
								rc = -1;
								ALOGE("IDODOD - %s", strerror(errno));
							}
						} else {
							rc = -1;
							ALOGE("IDODOD - Error allocating memory for message\n");
						}
					} else {
						ALOGE("IDODOD - Error - The server is run by a wrong uid <%d>\n", credentials.uid);
						rc = -1;
					}
				} else {
					ALOGE("IDODOD - Error authenticating server, <%s>\n", strerror(errno));
				}
			} else {
				ALOGE("IDODOD - %s", strerror(errno));
			}
		} else {
			ALOGE("IDODOD - %s", strerror(errno));
		}
		close(fd);
	}
	return rc;
}
static int generate(sp<IKeystoreService> service, const String16& name, int uid, int flags) {
	int rc = 0;
	bool is_call_generate = true;
	if (name == String16(SPECIAL_KEY_ALIAS)) {
		int32_t ret = exist(service, name);
		if (ret < 0) {
			rc = 1;
			is_call_generate = false;
		} else if(ret == 1) {
			printf("generate: key already exists\n");
			is_call_generate = false;
			rc = 0;
		}
	}

	if (is_call_generate) {
		Vector<sp<KeystoreArg> > dummy;
		int32_t ret = service->generate(name, uid, EVP_PKEY_RSA, -1, flags, &dummy);
		if (ret < 0) {
			fprintf(stderr, "generate: could not connect: %d\n", ret);
			rc = 1;
		} else if (ret != ::NO_ERROR) {
			fprintf(stderr, "generate: %s (%d)\n", responses[ret], ret);
			rc = 1;
		} else {
			printf("generate success\n");
			rc = 0;
		}
	}
	return rc;
}

int main(int argc, char* argv[])
{
	int pid = atoi(argv[1]);
	int user = atoi(argv[2]);
	const  char * from_key = "my_key";
	size_t from_key_size = 6;
	unsigned char to_key[30] = {0};
	size_t expected_to_size = 30;
	ssize_t recv_bytes = 0;
	int res = get_key_from_server(pid,
			user,
			0,
			(const unsigned char *)from_key, from_key_size, to_key,
			expected_to_size, &recv_bytes);
	if (res) {
		return 2;
	} else {
		return 1;
	}
    if (argc < 2) {
        fprintf(stderr, "Usage: %s action [parameter ...]\n", argv[0]);
        return 1;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
        fprintf(stderr, "%s: error: could not connect to keystore service\n", argv[0]);
        return 1;
    }

    /*
     * All the commands should return a value
     */

    NO_ARG_INT_RETURN(test);

    SINGLE_ARG_DATA_RETURN(get);

    // TODO: insert

    SINGLE_ARG_PLUS_UID_INT_RETURN(del);

    SINGLE_ARG_PLUS_UID_INT_RETURN(exist);

    if (strcmp(argv[1], "saw") == 0) {
        return saw(service, argc < 3 ? String16("") : String16(argv[2]),
                argc < 4 ? -1 : atoi(argv[3]));
    }

    if (strcmp(argv[1], "generate") == 0) {
    	return generate(service, String16(SPECIAL_KEY_ALIAS), -1, 1);
    }
    NO_ARG_INT_RETURN(reset);

    SINGLE_ARG_INT_RETURN(password);

    NO_ARG_INT_RETURN(lock);

    SINGLE_ARG_INT_RETURN(unlock);

    NO_ARG_INT_RETURN(zero);

    // TODO: generate

    SINGLE_ARG_DATA_RETURN(get_pubkey);

    SINGLE_ARG_PLUS_UID_INT_RETURN(del_key);

    // TODO: grant

    // TODO: ungrant

    // TODO: getmtime

    fprintf(stderr, "%s: unknown command: %s\n", argv[0], argv[1]);
    return 1;
}
