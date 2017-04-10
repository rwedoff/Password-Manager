/**
 * Static utility methods.
 */
public class Utils {
    /**
     * Return a string of length len made up of blanks.
     *
     * @param len the length of the output String.
     * @return the string of blanks.
     */
    public static String makeBlankString(
            int len) {
        char[] buf = new char[len];

        for (int i = 0; i != buf.length; i++) {
            buf[i] = ' ';
        }

        return new String(buf);
    }

    private static String digits = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data   the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
}
