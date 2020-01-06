/*
 * Copyright (C) 2019 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.idpass.tools;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * Base applet class for ID PASS project
 */
public abstract class IdpassApplet extends Applet implements ExtendedLength, AppletEvent {

    public static final short   SW_DEBUG               = (short) 0xF000;

    public final static short   LENGTH_MAC             = 8;
    public final static short   LENGTH_APDU_EXTENDED   = (short) 0x7FFF;

    private static final byte   INS_INITIALIZE_UPDATE  = (byte) 0x50;
    private static final byte   INS_BEGIN_RMAC_SESSION = (byte) 0x7A;
    private static final byte   INS_END_RMAC_SESSION   = (byte) 0x78;

    protected static final byte MASK_GP                = (byte) 0x80;
    protected static final byte MASK_SECURED           = (byte) 0x0C;

    private byte[]              apduData;
    protected byte              cla;
    protected byte              ins;
    protected byte              p1;
    protected byte              p2;

    protected SecureChannel       secureChannel;
    protected short aid_offset;
    protected byte aid_len;

    public boolean select() {
        // retrieve the handle of the Security Domain associated with this
        // applet.
        secureChannel = GPSystem.getSecureChannel();
        return true;
    }

    public void deselect() {
        // free the handle of the Security Domain associated with this applet.
        secureChannel.resetSecurity();
    }

    public void uninstall() {
        apduData = null;
    }

    public void process(APDU apdu) throws ISOException {
        try {
            byte[] buffer = apdu.getBuffer();
            cla = buffer[ISO7816.OFFSET_CLA];
            ins = buffer[ISO7816.OFFSET_INS];
            p1 = buffer[ISO7816.OFFSET_P1];
            p2 = buffer[ISO7816.OFFSET_P2];

            // ISO class
            if ((cla & (~MASK_SECURED)) == ISO7816.CLA_ISO7816) {
                if (ins == ISO7816.INS_SELECT) {
                    processSelect();
                    return;
                }
            }

            switch (ins) {
                case INS_INITIALIZE_UPDATE:
                case ISO7816.INS_EXTERNAL_AUTHENTICATE:
                case INS_BEGIN_RMAC_SESSION:
                case INS_END_RMAC_SESSION:
                    checkClaIsGp();
                    // allow to make contactless SCP 
                    // checkProtocolContacted();
                    processSecurity();
                    break;
                default:
                    processInternal(apdu);
            }

        } finally {
            if (apduData != null) {
                apduData = null;
                Utils.requestObjectDeletion();
            }
        }
    }

    protected abstract void processSelect();

    protected SecureChannel getSecurityObject() {
        return secureChannel;
    }

    protected void processSecurity() {
        // send to ISD
        short responseLength = secureChannel.processSecurity(APDU.getCurrentAPDU());
        if (responseLength != 0) {
            APDU.getCurrentAPDU().setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, responseLength);
        }
    }

    protected abstract void processInternal(APDU apdu) throws ISOException;

    protected boolean isAPDUProtocolContacted() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_DEFAULT);
    }

    protected byte[] getApduData() {
        if (APDU.getCurrentAPDU().getCurrentState() < APDU.STATE_PARTIAL_INCOMING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (apduData == null) {
            return APDU.getCurrentAPDUBuffer();
        } else {
            return apduData;
        }
    }

    protected short setIncomingAndReceiveUnwrap() {
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short bytesRead = APDU.getCurrentAPDU().setIncomingAndReceive();
        short apduDataOffset = APDU.getCurrentAPDU().getOffsetCdata();
        boolean isExtendedLengthData = apduDataOffset == ISO7816.OFFSET_EXT_CDATA;
        short overallLength = APDU.getCurrentAPDU().getIncomingLength();

        if (isExtendedLengthData) {
            apduData = new byte[LENGTH_APDU_EXTENDED];

            Util.arrayCopyNonAtomic(buffer, (short) 0, apduData, (short) 0, (short) (apduDataOffset + bytesRead));

            if (bytesRead != overallLength) { // otherwise we're finished, all bytes received
                short received = 0;
                do {
                    received = APDU.getCurrentAPDU().receiveBytes((short) 0);
                    Util.arrayCopyNonAtomic(buffer, (short) 0, apduData, (short) (apduDataOffset + bytesRead), received);
                    bytesRead += received;
                } while (!(received == 0 || bytesRead == overallLength));
            }

            buffer = apduData;

        }

        short result = overallLength;

        byte sl = secureChannel.getSecurityLevel();
        if ((sl & SecureChannel.C_DECRYPTION) != 0 || (sl & SecureChannel.C_MAC) != 0) {
            result =
                     (short) (secureChannel.unwrap(buffer, (short) 0, (short) (apduDataOffset + overallLength)) - apduDataOffset);

        }

        Util.arrayCopyNonAtomic(buffer, apduDataOffset, buffer, (short) 0, result);

        short bytesLeft = (short) (apduDataOffset - result);
        if (bytesLeft > 0) {
            Util.arrayFillNonAtomic(buffer, (short) (apduDataOffset - bytesLeft), bytesLeft, (byte) 0);
        }
        return result;

    }

    protected void setOutgoingAndSendWrap(byte[] buffer, short bOff, short len) {
        if (APDU.getCurrentAPDU().getCurrentState() < APDU.STATE_OUTGOING) {
            APDU.getCurrentAPDU().setOutgoing();
        }

        byte sl = secureChannel.getSecurityLevel();

        if ((sl & SecureChannel.R_ENCRYPTION) != 0 || (sl & SecureChannel.R_MAC) != 0) {
            len = secureChannel.wrap(buffer, bOff, len);
        }

        APDU.getCurrentAPDU().setOutgoingLength(len);
        APDU.getCurrentAPDU().sendBytesLong(buffer, bOff, len);
    }

    protected boolean isCheckC_MAC() {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0) || ((sl & SecureChannel.C_MAC) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;

        }
    }

    protected boolean isCheckC_DECRYPTION() {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0) || ((sl & SecureChannel.C_DECRYPTION) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }

    /**
     * Check whether it is GP class command
     * 
     * @param cla
     */
    protected void checkClaIsGp() {
        if ((cla & MASK_GP) != MASK_GP) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /**
     * Check whether it is Interindustry class command
     * 
     * @param cla
     */
    protected void checkClaIsInterindustry() {
        if ((cla & MASK_GP) != ISO7816.CLA_ISO7816) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    protected void checkProtocolContacted() {
        if (!isAPDUProtocolContacted()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
