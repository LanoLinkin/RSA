import java.io.IOException;
import java.util.Scanner;

public class test_rsa_file{
    public static void main(String[] args) throws IOException {
        rsa rsa = new rsa();
        rsa.KeyGen();
        Scanner sc = new Scanner(System.in);
        boolean process = true;
        System.out.println("Electronic signature based on RSA:" +
        "\n1.sign\n2.verify\n3.exit" + 
        "\nto select, enter the word actions (from the possible functionality)");
        while (process) {
            String res = sc.nextLine();
            switch (res){
                case "1": 
                    System.out.println("Enter the name of the file you want to sign");
                    String fileName = sc.nextLine();
                    rsa.signFile(fileName, "prkey");
                    System.out.println("something else?");
                    break;

                case "2":
                    System.out.println("Enter the name of the signed file");
                    String SignedFileName = sc.nextLine().stripTrailing();
                    if(rsa.verify(SignedFileName, "pbkey") == true)
                        System.out.println("Verified");
                    else
                        System.out.println("Not verified");
                    System.out.println("something else?");
                    break;

                case "3":
                    System.out.println("Happy New Year");
                    sc.close();
                    process = false;
                    return;
            }
        }
        sc.close();
    }
}
