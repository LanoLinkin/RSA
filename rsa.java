import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 

public class rsa {
    public void signFile (String FileName, String keyFile) throws IOException{
        String hash = getHash(FileName);
        String sign = encrypt(hash, keyFile);
        write("signature.txt", sign);
    }
    
    public boolean verify(String SignedFileName, String keyFile) throws IOException{
        String hash = getHash(SignedFileName);
        String signature = readFile("signature.txt");
        String s = decrypt(signature, keyFile);
        return s.equals(hash);
    }

    public String encrypt(String hash, String keyFile) throws IOException{
        BigInteger[] key = readKeyFile(keyFile);
        BigInteger bg = new BigInteger(hash, 16);
        BigInteger res = bg.modPow(key[0], key[1]);
        String encryptMessage = res.toString(10);
        return encryptMessage;
    }
    
    public String decrypt(String encryptedMessage, String keyFile) throws IOException{
        BigInteger[] key = readKeyFile(keyFile);
        BigInteger bg = new BigInteger(encryptedMessage, 10);
        BigInteger res = bg.modPow(key[0], key[1]);
        String decryptMessage = res.toString(16);
        return decryptMessage;
    }
    
    public static BigInteger getE(BigInteger phi){
        BigInteger e = BigInteger.ONE;
        boolean process = true;
        while (process){
            e = e.add(BigInteger.ONE);
            if (extended_gcd(e, phi).compareTo(BigInteger.ONE) == 0 && e.compareTo(phi) < 0){
                process = false;
            }
        }
        return e;
    }

    public static BigInteger getD(BigInteger e, BigInteger phi){
        BigInteger d = BigInteger.ZERO;
        BigInteger k = BigInteger.ZERO;
        while (d==BigInteger.ZERO){
            k = k.add(BigInteger.ONE);
            if (phi.multiply(k).add(BigInteger.ONE).mod(e).compareTo(BigInteger.ZERO) == 0){
                d = d.add(phi.multiply(k).add(BigInteger.ONE).divide(e));
            }
        }
        return d;
    }    

    public void KeyGen() throws IOException {
        BigInteger firstPrimeNum = getPrime();
        BigInteger secondPrimeNum = getPrime();
        BigInteger n = firstPrimeNum.multiply(secondPrimeNum); // вычисление модуля
        BigInteger phi = firstPrimeNum.subtract(BigInteger.ONE).multiply(secondPrimeNum.subtract(BigInteger.ONE)); // функция Эйлера
        BigInteger e = getE(phi);
        BigInteger d = getD(e, phi);
        while (d.compareTo(BigInteger.ZERO) < 0) {
            d = d.add(phi);
        }
        BigInteger[] pbKey = new BigInteger[] { e, n };
        BigInteger[] prKey = new BigInteger[] { d, n };

        writeKeyToFile("pbkey", pbKey);
        writeKeyToFile("prkey", prKey);
    }

    private static void writeKeyToFile(String fileName, BigInteger[] key) throws IOException {
        File file = new File(fileName);
        FileWriter fw = new FileWriter(file);
        fw.write(toString(key, 0));
        fw.write(toString(key, 1));
        fw.close();
    }

    public static BigInteger[] readKeyFile(String filename) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String fString = "";
        String sString = "";
        fString = br.readLine();
        sString = br.readLine();
        br.close();
        return new BigInteger[] { new BigInteger(fString), new BigInteger(sString) };
    }

    private static String toString(BigInteger[] key, int i) {
        return key[i] + "\n";
    }

    public static BigInteger extended_gcd(BigInteger a, BigInteger b) {
        return a.gcd(b);
    }
    

    public static BigInteger getPrime() {
        BigInteger minLimit = new BigInteger("350000000000000000000000000000000000000");
        BigInteger maxLimit = new BigInteger("350000000000000000000000000000000000000000000000000");
        BigInteger bigInteger = maxLimit.subtract(minLimit);
        SecureRandom randNum = new SecureRandom();
        int len = maxLimit.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(minLimit) < 0)
            res = res.add(minLimit);
        if (res.compareTo(bigInteger) >= 0)
            res = res.mod(bigInteger).add(minLimit);
        BigInteger bi = BigInteger.probablePrime(1024, randNum);
        if (isPrime(bi) == false)
            getPrime(); 
        return bi;
    }

    public static boolean isPrime(BigInteger n, int precision) {
 
        if (n.compareTo(new BigInteger("341550071728321")) >= 0) {
            return n.isProbablePrime(precision);
        }
 
        int intN = n.intValue();
        if (intN == 1 || intN == 4 || intN == 6 || intN == 8) return false;
        if (intN == 2 || intN == 3 || intN == 5 || intN == 7) return true;
 
        int[] primesToTest = getPrimesToTest(n);
        if (n.equals(new BigInteger("3215031751"))) {
            return false;
        }
        BigInteger d = n.subtract(BigInteger.ONE);
        BigInteger s = BigInteger.ZERO;
        while (d.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            d = d.shiftRight(1);
            s = s.add(BigInteger.ONE);
        }
        for (int a : primesToTest) {
            if (try_composite(a, d, n, s)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isPrime(BigInteger n) {
        return isPrime(n, 100);
    }

    private static int[] getPrimesToTest(BigInteger n) {
        if (n.compareTo(new BigInteger("3474749660383")) >= 0) {
            return new int[]{2, 3, 5, 7, 11, 13, 17};
        }
        if (n.compareTo(new BigInteger("2152302898747")) >= 0) {
            return new int[]{2, 3, 5, 7, 11, 13};
        }
        if (n.compareTo(new BigInteger("118670087467")) >= 0) {
            return new int[]{2, 3, 5, 7, 11};
        }
        if (n.compareTo(new BigInteger("25326001")) >= 0) {
            return new int[]{2, 3, 5, 7};
        }
        if (n.compareTo(new BigInteger("1373653")) >= 0) {
            return new int[]{2, 3, 5};
        }
        return new int[]{2, 3};
    }

    private static boolean try_composite(int a, BigInteger d, BigInteger n, BigInteger s) {
        BigInteger aB = BigInteger.valueOf(a);
        if (aB.modPow(d, n).equals(BigInteger.ONE)) {
            return false;
        }
        for (int i = 0; BigInteger.valueOf(i).compareTo(s) < 0; i++) {
            if (aB.modPow(BigInteger.valueOf(2).pow(i).multiply(d), n).equals(n.subtract(BigInteger.ONE))) {
                return false;
            }
        }
        return true;
    }

    public static byte[] getSHA(String input) throws NoSuchAlgorithmException { // Статический метод getInstance вызывается с хэшированием SHA
        MessageDigest md = MessageDigest.getInstance("SHA-256"); 
        // метод digest () вызван
        // рассчитать дайджест сообщения ввода
        // и возвращаем массив байт
        return md.digest(input.getBytes(StandardCharsets.US_ASCII));
    }

    public static String toHexString(byte[] hash) {
        String hex = "";
        for (byte b : hash) {
            hex += String.format("%02x", b);
        }
        return hex;
    }

    public String getHash (String fileName) throws IOException{
       String s1 = readFile(fileName);
        try {
            byte[] tmp = getSHA(s1);
            String res = toHexString(tmp);
            return res;
        } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
           return s1;
        }
    }

    public static String readFile(String fileName) throws FileNotFoundException {//Определяем файл
        File file = new File(fileName);
        StringBuilder sb = new StringBuilder();
        file.exists();
        try {
            BufferedReader in = new BufferedReader(new FileReader( file.getAbsoluteFile()));
            try {//В цикле построчно считываем файл
                String s;
                while ((s = in.readLine()) != null) {
                    sb.append(s);
                    sb.append("\n");
                }
            } finally {//закрываем файл
                in.close();
            }
        } catch(IOException e) {
            throw new RuntimeException(e);
        }//Возвращаем полученный текст с файла
        return sb.toString().replaceAll("\n", "");
    }

    public static void write(String fileName, String text) {//Определяем файл
        File file = new File(fileName);
        try {//проверяем, что если файл не существует то создаем его
            if(!file.exists()){
                file.createNewFile();
            }
            PrintWriter out = new PrintWriter(file.getAbsoluteFile());//PrintWriter обеспечит возможности записи в файл
            try {//Записываем текст в файл
                out.print(text);
            } finally {//закрываем файл
                out.close();
            }
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }
}