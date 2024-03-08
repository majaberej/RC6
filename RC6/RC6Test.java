import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RC6Test {

    @Test
    void testVector1(){
        byte[] test1 = RC6.hexStringToByteArray("02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1");
        byte[] key1 =  RC6.hexStringToByteArray("01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78");
        byte[] testResult = RC6.hexStringToByteArray("52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18");

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

    @Test
    void testVector2(){
        byte[] test1 = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        byte[] key1 =  {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        byte[] testResult = RC6.hexStringToByteArray("8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e");

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

    @Test
    void testVector3(){
        byte[] test1 = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        byte[] key1 =  {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        byte[] testResult = {0x6c, (byte) 0xd6, 0x1b, (byte) 0xcb, 0x19, 0x0b, 0x30, 0x38, 0x4e, (byte) 0x8a, 0x3f, 0x16, (byte) 0x86, (byte) 0x90, (byte) 0xae, (byte) 0x82};

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

    @Test
    void testVector4(){
        byte[] test1 = RC6.hexStringToByteArray("02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1");
        byte[] key1 =  RC6.hexStringToByteArray("01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0");
        byte[] testResult = RC6.hexStringToByteArray("68 83 29 d0 19 e5 05 04 1e 52 e9 2a f9 52 91 d4");

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

    @Test
    void testVector5(){
        byte[] test1 = RC6.hexStringToByteArray("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        byte[] key1 =  RC6.hexStringToByteArray("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        byte[] testResult = RC6.hexStringToByteArray("8f 5f bd 05 10 d1 5f a8 93 fa 3f da 6e 85 7e c2");

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

    @Test
    void testVector6(){
        byte[] test1 = RC6.hexStringToByteArray("02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1");
        byte[] key1 =  RC6.hexStringToByteArray("01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe");
        byte[] testResult = RC6.hexStringToByteArray("c8 24 18 16 f0 d7 e4 89 20 ad 16 a1 67 4e 5d 48");

        RC6.keySchedule(key1);
        byte[] result = RC6.encrypt(test1);
        byte[] resultDecrypt = RC6.decrypt(result);

        assertArrayEquals(testResult, result);
        assertArrayEquals(test1, resultDecrypt);
    }

}