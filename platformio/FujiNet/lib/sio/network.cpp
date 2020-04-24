#include "network.h"
#include "networkProtocol.h"
#include "networkProtocolTCP.h"
#include "networkProtocolUDP.h"
#include "networkProtocolHTTP.h"

/**
 * Allocate input/output buffers
 */
bool sioNetwork::allocate_buffers()
{
    rx_buf = (byte *)malloc(INPUT_BUFFER_SIZE);
    tx_buf = (byte *)malloc(OUTPUT_BUFFER_SIZE);
    sp_buf = (byte *)malloc(SPECIAL_BUFFER_SIZE);

    if ((rx_buf == nullptr) || (tx_buf == nullptr) || (sp_buf == nullptr))
    {
        return false;
    }
    else
    {
        memset(rx_buf, 0, INPUT_BUFFER_SIZE);
        memset(tx_buf, 0, OUTPUT_BUFFER_SIZE);
        memset(sp_buf, 0, SPECIAL_BUFFER_SIZE);
        return true;
    }
}

/**
 * Deallocate input/output buffers
 */
void sioNetwork::deallocate_buffers()
{
    if (rx_buf != nullptr)
        free(rx_buf);

    if (tx_buf != nullptr)
        free(tx_buf);

    if (sp_buf != nullptr)
        free(sp_buf);
}

bool sioNetwork::open_protocol()
{
    if (strcmp(deviceSpec.protocol, "TCP") == 0)
    {
        protocol = new networkProtocolTCP();
        return true;
    }
    else if (strcmp(deviceSpec.protocol, "UDP") == 0)
    {
        protocol = new networkProtocolUDP();
        if (protocol != nullptr)
            protocol->set_saved_rx_buffer(rx_buf, &rx_buf_len);
        return true;
    }
    else if (strcmp(deviceSpec.protocol, "HTTP") == 0)
    {
        protocol = new networkProtocolHTTP();
        return true;
    }
    else if (strcmp(deviceSpec.protocol, "HTTPS") == 0)
    {
        protocol = new networkProtocolHTTP();
        return true;
    }
    else
    {
        return false;
    }
}

void sioNetwork::sio_open()
{
    char inp[256];

    sio_ack();

    if (protocol != nullptr)
    {
        delete protocol;
        deallocate_buffers();
    }

    deviceSpec.clear();
    memset(&inp, 0, sizeof(inp));
    memset(&status_buf.rawData, 0, sizeof(status_buf.rawData));

    sio_to_peripheral((byte *)&inp, sizeof(inp));

#ifdef DEBUG
    Debug_printf("Open: %s\n", inp);
#endif

    if (deviceSpec.parse(inp) == false)
    {
#ifdef DEBUG
        Debug_printf("Invalid devicespec\n");
#endif
        status_buf.error = 165;
        sio_error();
        return;
    }

    if (allocate_buffers() == false)
    {
#ifdef DEBUG
        Debug_printf("Could not allocate memory for buffers\n");
#endif
        status_buf.error = 129;
        sio_error();
        return;
    }

    if (open_protocol() == false)
    {
#ifdef DEBUG
        Debug_printf("Could not open protocol.\n");
#endif
        status_buf.error = 128;
        sio_error();
        return;
    }

    if (!protocol->open(&deviceSpec, &cmdFrame))
    {
#ifdef DEBUG
        Debug_printf("Protocol unable to make connection.");
#endif
        protocol->close();
        delete protocol;
        protocol = nullptr;
        status_buf.error = 170;
        sio_error();
        return;
    }

    aux1 = cmdFrame.aux1;
    aux2 = cmdFrame.aux2;
    sio_complete();
}

void sioNetwork::sio_close()
{
#ifdef DEBUG
    Debug_printf("Close.\n");
#endif
    sio_ack();

    status_buf.error = 0; // clear error

    if (protocol == nullptr)
    {
        sio_complete();
        return;
    }

    if (protocol->close())
        sio_complete();
    else
        sio_error();

    delete protocol;
    protocol = nullptr;

    deallocate_buffers();
}

void sioNetwork::sio_read()
{
    sio_ack();
#ifdef DEBUG
    Debug_printf("Read %d bytes\n", cmdFrame.aux2 * 256 + cmdFrame.aux1);
#endif
    if (protocol == nullptr)
    {
        err = true;
        status_buf.error = 128;
    }
    else
    {
        rx_buf_len = cmdFrame.aux2 * 256 + cmdFrame.aux1;
        err = protocol->read(rx_buf, cmdFrame.aux2 * 256 + cmdFrame.aux1);

        // Convert CR and/or LF to ATASCII EOL
        // 1 = CR, 2 = LF, 3 = CR/LF
        if (aux2 > 0)
        {
            for (int i = 0; i < rx_buf_len; i++)
            {
                switch (aux2)
                {
                case 1:
                    if (rx_buf[i] == 0x0D)
                        rx_buf[i] = 0x9B;
                    break;
                case 2:
                    if (rx_buf[i] == 0x0A)
                        rx_buf[i] = 0x9B;
                    break;
                case 3:
                    if ((rx_buf[i] == 0x0D) && (rx_buf[i + 1] == 0x0A))
                    {
                        memmove(&rx_buf[i - 1], &rx_buf[i], rx_buf_len);
                        rx_buf[i] = 0x9B;
                        rx_buf_len--;
                    }
                    break;
                }
            }
        }
    }
    sio_to_computer(rx_buf, rx_buf_len, err);
}

void sioNetwork::sio_write()
{
#ifdef DEBUG
    Debug_printf("Write %d bytes\n", cmdFrame.aux2 * 256 + cmdFrame.aux1);
#endif

    sio_ack();

    memset(tx_buf, 0, OUTPUT_BUFFER_SIZE);

    if (protocol == nullptr)
    {
#ifdef DEBUG
        Debug_printf("Not connected\n");
#endif
        err = true;
        status_buf.error = 128;
        sio_error();
    }
    else
    {
        ck = sio_to_peripheral(tx_buf, sio_get_aux());
        tx_buf_len = cmdFrame.aux2 * 256 + cmdFrame.aux1;

        // Handle EOL to CR/LF translation.
        // 1 = CR, 2 = LF, 3 = CR/LF

        if (aux2 > 0)
        {
            for (int i = 0; i < tx_buf_len; i++)
            {
                switch (aux2)
                {
                case 1:
                    if (tx_buf[i] == 0x9B)
                        tx_buf[i] = 0x0D;
                    break;
                case 2:
                    if (tx_buf[i] == 0x9B)
                        tx_buf[i] = 0x0A;
                    break;
                case 3:
                    if (tx_buf[i] == 0x9B)
                    {
                        memmove(&tx_buf[i + 1], &tx_buf[i], tx_buf_len);
                        tx_buf[i] = 0x0D;
                        tx_buf[i + 1] = 0x0A;
                        tx_buf_len++;
                    }
                    break;
                }
            }
        }

        if (!protocol->write(tx_buf, tx_buf_len))
        {
            sio_complete();
        }
        else
        {
            sio_error();
        }
    }
}

void sioNetwork::sio_status()
{
    sio_ack();
#ifdef DEBUG
    Debug_printf("STATUS\n");
#endif
    if (!protocol)
    {
        status_buf.rawData[0] =
            status_buf.rawData[1] = 0;

        status_buf.rawData[2] = WiFi.isConnected();
        err = false;
    }
    else
    {
        err = protocol->status(status_buf.rawData);
    }
#ifdef DEBUG
    Debug_printf("Status bytes: %02x %02x %02x %02x\n", status_buf.rawData[0], status_buf.rawData[1], status_buf.rawData[2], status_buf.rawData[3]);
#endif
    sio_to_computer(status_buf.rawData, 4, err);
}

void sioNetwork::sio_special()
{
    err = false;
    if (protocol == nullptr)
    {
        err = true;
        status_buf.error = OPEN_STATUS_NOT_CONNECTED;
    }
    else if (cmdFrame.comnd == 0xFF) // Get DSTATS for protocol command.
    {
        byte ret;
        sio_ack();
        if (protocol->special_supported_00_command(cmdFrame.aux1))
            ret = 0x00;
        else if (protocol->special_supported_40_command(cmdFrame.aux1))
            ret = 0x40;
        else if (protocol->special_supported_80_command(cmdFrame.aux1))
            ret = 0x80;
        else
            ret = 0xFF;
        sio_to_computer(&ret, 1, false);
    }
    else if (protocol->special_supported_00_command(cmdFrame.comnd))
    {
        sio_ack();
        sio_special_00();
    }
    else if (protocol->special_supported_40_command(cmdFrame.comnd))
    {
        sio_ack();
        sio_special_40();
    }
    else if (protocol->special_supported_80_command(cmdFrame.comnd))
    {
        sio_ack();
        sio_special_80();
    }

    if (err == true) // Unsupported command
        sio_nak();

    // sio_completes() happen in sio_special_XX()
}

// For commands with no payload.
void sioNetwork::sio_special_00()
{
    if (!protocol->special(sp_buf, sp_buf_len, &cmdFrame))
        sio_complete();
    else
        sio_error();
}

// For commands with Peripheral->Computer payload
void sioNetwork::sio_special_40()
{
    err = protocol->special(sp_buf, sp_buf_len, &cmdFrame);
    sio_to_computer(sp_buf, sp_buf_len, err);
}

// For commands with Computer->Peripheral payload
void sioNetwork::sio_special_80()
{
    sio_to_peripheral(sp_buf, sp_buf_len);
    err = protocol->special(sp_buf, sp_buf_len, &cmdFrame);
}

void sioNetwork::sio_assert_interrupts()
{
    if (protocol != nullptr)
    {
        protocol->status(status_buf.rawData); // Prime the status buffer
        if (status_buf.rx_buf_len > 0)
        {
            digitalWrite(PIN_PROC, LOW);
            delayMicroseconds(200);
            digitalWrite(PIN_PROC, HIGH);
        }
        // digitalWrite(PIN_PROC, (protocol->assertProceed == true ? LOW : HIGH));
    }
}

void sioNetwork::sio_process()
{
    switch (cmdFrame.comnd)
    {
    case 'O':
        sio_open();
        break;
    case 'C':
        sio_close();
        break;
    case 'R':
        sio_read();
        break;
    case 'W':
        sio_write();
        break;
    case 'S':
        sio_status();
        break;
    default:
        sio_special();
        break;
    }
}