import java.util.Collections;
import java.util.Scanner;

public class RC6 {
    private final static int w = 32;
    private final static int r = 20;
    private final static int P = 0xB7E15163;
    private final static int Q = 0x9E3779b9;

    public static int log2(int N)
    {
        return (int)(Math.log(N) / Math.log(2));
    }

    private final static int log_w = log2(w);
    private static final int[] S = new int[2*(r + 2)];

    private static int rightRotate(int n, int d) {
        return (n >>> d) | (n << (w - d));
    }

    private static int leftRotate(int n, int d) {
        return (n << d) | (n >>> (w - d));
    }

    private static byte[] convertToHex(int regA,int regB, int regC, int regD){
        int[] data = new int[4];
        byte[] text = new byte[w / 2];
        data[0] = regA;
        data[1] = regB;
        data[2] = regC;
        data[3] = regD;

        for(int i = 0;i < text.length;i++){
            text[i] = (byte)((data[i/4] >>> (i%4)*8) & 0xff);
        }

        return text;
    }


    static byte[] encrypt(byte[] plainTextBlock){

        int[] registers = new int[4];
        for(int i=0;i<16;i+=4){
            registers[i/4] = ((plainTextBlock[i] & 0xff) | (plainTextBlock[i+1] & 0xff) << 8 |
                    (plainTextBlock[i+2] & 0xff) << 16| (plainTextBlock[i+3] & 0xff)<<24);
        }

        int A = registers[0];
        int B = registers[1];
        int C = registers[2];
        int D = registers[3];

        B = B + S[0];
        D = D + S[1];

        for(int i=1; i<=r; i++){
            int t = leftRotate(B * (2*B + 1),log_w);
            int u = leftRotate(D * (2*D + 1),log_w);
            A = leftRotate(A ^ t,u) + S[2*i];
            C = leftRotate(C ^ u,t) + S[2*i + 1];
            int swap = A;
            A = B;
            B = C;
            C = D;
            D = swap;
        }

        A = A + S[r*2 + 2];
        C = C + S[r*2 + 3];
        return convertToHex(A, B, C, D);
    }

    public static byte[] hexStringToByteArray(String hexString) {
        hexString = hexString.replaceAll("\\s", ""); // Remove all whitespace characters from the hex string
        if(hexString.length() < 32)
            hexString = hexString + String.join("", Collections.nCopies(32 - hexString.length(), "0"));
        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return byteArray;
    }

    static byte[] decrypt(byte[] plainTextBlock){

        int[] registers = new int[4];
        for(int i=0;i<16;i+=4){
            registers[i/4] = ((plainTextBlock[i] & 0xff) | (plainTextBlock[i+1] & 0xff) << 8 |
                    (plainTextBlock[i+2] & 0xff) << 16| (plainTextBlock[i+3] & 0xff)<<24);
        }

        int A = registers[0];
        int B = registers[1];
        int C = registers[2];
        int D = registers[3];

        C = C - S[2*r + 3];
        A = A - S[2*r + 2];

        for(int i=r; i>=1; i--){
            int swap = D;
            D = C;
            C = B;
            B = A;
            A = swap;
            int u = leftRotate(D * (2*D + 1),log_w);
            int t = leftRotate(B * (2*B + 1),log_w);
            C = (rightRotate((C - S[2*i + 1]),t))^u;
            A = (rightRotate((A - S[2*i]), u)) ^ t;
        }

        D = D - S[1];
        B = B - S[0];
        return convertToHex(A,B,C,D);
    }


    static void keySchedule(byte[] key){
        int bytes = w / 8;
        int c = key.length / bytes;
        int[] L = new int[c];
        int index = 0;

        for(int i = 0; i < c; i++){
            L[i] = ((key[index++]) & 0xff | (key[index++] & 0xff) << 8 | (key[index++] & 0xff) << 16 |
                    (key[index++] & 0xff) << 24);
        }
        S[0] = P;

        for(int i=1; i<=2*r +3; i++){
            S[i] = S[i-1] + Q;
        }

        int A = 0, B = 0, i = 0,j = 0;
        int v = 3 * Math.max(c, 2*(r+2));

        for(int s=1; s<=v; s++){
            A = S[i] = leftRotate(S[i] + A + B,3);
            B = L[j] = leftRotate(L[j] + A + B, A+B);
            i = (i+1) % (2*(r+2));
            j = (j+1) % c;
        }
        System.out.println("\nFinished\n");
    }



    public static void main(String[] args) {
        byte[] byteMessage;
        byte[] byteKey;

        // Example input
        // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        Scanner in = new Scanner(System.in);
        System.out.println("Enter the message as a hexadecimal String.");
        String hexMessage = in.nextLine();
        System.out.println("Enter the key as a hexadecimal String.");
        String hexKey = in.nextLine();

        byteMessage = hexStringToByteArray(hexMessage);
        byteKey = hexStringToByteArray(hexKey);

        keySchedule(byteKey);
        byte[] ciphertext = encrypt(byteMessage);
        byte[] decryptedPlaintext = decrypt(ciphertext);

        System.out.println("Ciphertext:");
        for (byte b : ciphertext) {
            System.out.print(Integer.toHexString(b & 0xff));
        }
        System.out.println();

        System.out.println("\nDecrypted plaintext:");
        for (byte b : decryptedPlaintext) {
            System.out.print(Integer.toHexString(b & 0xff));
        }
    }
}