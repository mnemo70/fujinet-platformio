/**
 * SSH protocol implementation
 */

#include "../../include/debug.h"

#include "status_error_codes.h"

#include "SSH.h"

#define RXBUF_SIZE 65535

NetworkProtocolSSH::NetworkProtocolSSH(string *rx_buf, string *tx_buf, string *sp_buf)
    : NetworkProtocol(rx_buf, tx_buf, sp_buf)
{
    Debug_printf("NetworkProtocolSSH::NetworkProtocolSSH(%p,%p,%p)\n", rx_buf, tx_buf, sp_buf);
    rxbuf = (char *)heap_caps_malloc(RXBUF_SIZE, MALLOC_CAP_SPIRAM);
}

NetworkProtocolSSH::~NetworkProtocolSSH()
{
    Debug_printf("NetworkProtocolSSH::~NetworkProtocolSSH()\n");
    heap_caps_free(rxbuf);
}

bool NetworkProtocolSSH::open(EdUrlParser *urlParser, cmdFrame_t *cmdFrame)
{
    NetworkProtocol::open(urlParser, cmdFrame);
    int rc;
    int method;

    // TODO Only do this once.
    libssh_begin();

    if ((login->empty()) && (password->empty()))
    {
        error = NETWORK_ERROR_INVALID_USERNAME_OR_PASSWORD;
        return true;
    }

    // Port 22 by default.
    if (urlParser->port.empty())
    {
        urlParser->port = 22;
    }

    Debug_printf("NetworkProtocolSSH::open() - Creating session.\n");
    session = ssh_new();
    if (session == nullptr)
    {
        Debug_printf("Could not create session. aborting.\n");
        error = NETWORK_ERROR_NOT_CONNECTED;
        return true;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, urlParser->hostName.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT_STR, urlParser->port.c_str());

    //fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    rc = ssh_get_server_publickey(session, &fingerprint);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(fingerprint,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(fingerprint);
    if (rc < 0) {
        return -1;
    }
    Debug_printf("SSH Host Key Fingerprint is: ");

    for (int i = 0; i < 20; i++)
    {
        Debug_printf("%02X", (unsigned char)hash[i]);
        if (i < 19)
            Debug_printf(":");
    }

    Debug_printf("\n");

    ssh_userauth_none(session, login->c_str());
    method = ssh_userauth_list(session, NULL);
    Debug_printf("Authentication methods: 0x%x\n", method);

    if ((method & SSH_AUTH_METHOD_PASSWORD) == 0) {
        error = NETWORK_ERROR_GENERAL;
        Debug_printf("Authentication by password not supported by host.\n");
        return true;
    }

    if (ssh_userauth_password(session, login->c_str(), password->c_str()) != SSH_OK)
    {
        error = NETWORK_ERROR_GENERAL;
        Debug_printf("Could not perform userauth.\n");
        return true;
    }

    channel = ssh_channel_new(session);

    if (!channel)
    {
        error = NETWORK_ERROR_GENERAL;
        Debug_printf("Could not open session channel.\n");
        return true;
    }

    // "vanilla"?
    if (ssh_channel_request_pty(channel) != SSH_OK)
    {
        error = NETWORK_ERROR_GENERAL;
        Debug_printf("Could not request pty\n");
        return true;
    }

    if (ssh_channel_request_shell(channel) != SSH_OK)
    {
        error = NETWORK_ERROR_GENERAL;
        Debug_printf("Could not open shell on channel\n");
        return true;
    }

    ssh_channel_set_blocking(channel, 0);

    // At this point, we should be able to talk to the shell.
    Debug_printf("Shell opened.\n");

    return false;
}

bool NetworkProtocolSSH::close()
{
    ssh_disconnect(session);
    ssh_free(session);
    return false;
}

bool NetworkProtocolSSH::read(unsigned short len)
{
    // Ironically, All of the read is handled in available().
    return false;
}

bool NetworkProtocolSSH::write(unsigned short len)
{
    bool err = false;

    len = translate_transmit_buffer();
    ssh_channel_write(channel, transmitBuffer->data(), len);

    // Return success
    error = 1;
    transmitBuffer->erase(0, len);

    return err;
}

bool NetworkProtocolSSH::status(NetworkStatus *status)
{
    status->rxBytesWaiting = available();    
    status->connected = ssh_channel_is_eof(channel) == 0 ? 1 : 0;
    status->error = ssh_channel_is_eof(channel) == 0 ? 1 : NETWORK_ERROR_END_OF_FILE;
    NetworkProtocol::status(status);
    return false;
}

uint8_t NetworkProtocolSSH::special_inquiry(uint8_t cmd)
{
    return 0xFF; // selected command not implemented.
}

bool NetworkProtocolSSH::special_00(cmdFrame_t *cmdFrame)
{
    return false;
}

bool NetworkProtocolSSH::special_40(uint8_t *sp_buf, unsigned short len, cmdFrame_t *cmdFrame)
{
    return false;
}

bool NetworkProtocolSSH::special_80(uint8_t *sp_buf, unsigned short len, cmdFrame_t *cmdFrame)
{
    return false;
}

unsigned short NetworkProtocolSSH::available()
{
    if (receiveBuffer->length() == 0)
    {
        if (ssh_channel_is_eof(channel) == 0)
        {
            int len = ssh_channel_read(channel, rxbuf, RXBUF_SIZE, false);
            if (len != SSH_AGAIN)
            {
                receiveBuffer->append(rxbuf, len);
                translate_receive_buffer();
            }
        }
    }

    return receiveBuffer->length();
}
