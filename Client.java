package com.company;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.UUID;

public class Client extends JFrame {
    private static Socket connection;
    private static BufferedReader input;
    private static BufferedWriter output;
    private static boolean workClient = false;

    static JPanel panelUsername, panelPassword, panelButton;
    static JLabel labelUsername, labelPassword;
    static JTextField inputUsername;
    static JPasswordField inputPassword;
    static JButton connect, authenticationButton, registrationButton, disconnect;

    static Toolkit kit = Toolkit.getDefaultToolkit();
    static Dimension screenSize = kit.getScreenSize();
    TestActionListener testActionListener = new TestActionListener();

    private static int lx = screenSize.width;
    private static int ly = screenSize.height;

    private static ArrayList<String> usernameList = new ArrayList<>();
    private static ArrayList<Integer> generatorList = new ArrayList<>();
    private static ArrayList<Integer> safePrimeList = new ArrayList<>();
    private static ArrayList<String> options = new ArrayList<>();
    private static int[] simpleNumber = {499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,643,647,653,659,661,673,677,683,691,701};
    private static final int k = 3;
    private static int a;
    private static String username;
    private static String password;
    private static String salt;
    private static int passwordVerifier;
    private static int safePrime;
    private static long hashSaltPassword;
    private static int generator;
    private static int computationalNumber;

    public Client(String name){
        super(name);
        createGUI();
    }

    public void createGUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        setBounds(lx / 3, ly / 2, 500, 150);
        setResizable(false);

        panelUsername = new JPanel();
        panelPassword = new JPanel();
        panelButton = new JPanel();

        labelUsername = new JLabel("login          ");
        labelPassword = new JLabel("password");

        inputUsername = new JTextField(10);
        inputPassword = new JPasswordField(10);

        connect = new JButton("Connect");
        registrationButton = new JButton("Registration");
        authenticationButton = new JButton("Authorization");
        disconnect = new JButton("Disconnect");

        panelUsername.add(labelUsername);
        panelUsername.add(inputUsername);

        panelPassword.add(labelPassword);
        panelPassword.add(inputPassword);

        panelButton.add(connect);
        panelButton.add(registrationButton);
        panelButton.add(authenticationButton);
        panelButton.add(disconnect);

        getContentPane().add(BorderLayout.NORTH, panelUsername);
        getContentPane().add(BorderLayout.CENTER, panelPassword);
        getContentPane().add(BorderLayout.SOUTH, panelButton);

        setVisible(true);

        connect.addActionListener(testActionListener);
        registrationButton.addActionListener(testActionListener);
        authenticationButton.addActionListener(testActionListener);
        disconnect.addActionListener(testActionListener);
    }

    public void sendRegistrationParameters(){
        try{
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

            output.write("registration" + "\n");
            output.flush();

            output.write(username + "\n");
            output.flush();

            output.write(salt + "\n");
            output.flush();

            output.write(passwordVerifier + "\n");
            output.flush();

            output.write(generator + "\n");
            output.flush();

            output.write(safePrime + "\n");
            output.flush();
        }catch (Exception e){
            JOptionPane.showMessageDialog(null,"Server is not connection!");
            workClient = false;
        }
    }

    public void sendAuthorizationParameters(){
        try{
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

            output.write("authorization" + "\n");
            output.flush();

            output.write(username + "\n");
            output.flush();

            output.write(computationalNumber + "\n");
            output.flush();

        }catch (Exception e){
            JOptionPane.showMessageDialog(null,"Server is not connection!");
            workClient = false;
        }
    }

    public void checkAuthenticationParameters(){
        try{
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

            output.write("authentication" + "\n");
            output.flush();

            int B = Integer.valueOf(input.readLine());

            salt = input.readLine();

            System.out.println("\n" + "Authentication:");
            System.out.println("A = " + computationalNumber);
            System.out.println("B = " + B);
            System.out.println("salt = " + salt);

              if (B != 0) {
                  options.add(String.valueOf(computationalNumber));
                  options.add(String.valueOf(B));
                  BigInteger u = BigInteger.valueOf(hashFunction(options));
                  options.clear();


                  options.add(salt);
                  options.add(password);
                  hashSaltPassword = hashFunction(options);
                  options.clear();

                  BigInteger tmp = new BigInteger(String.valueOf(generator));

                  tmp = tmp.pow((int) hashSaltPassword);

                  tmp = tmp.mod(BigInteger.valueOf(safePrime));

                  tmp = tmp.multiply(BigInteger.valueOf(k));

                  BigInteger S = new BigInteger(String.valueOf(B - Integer.valueOf(String.valueOf(tmp))));

                  BigInteger tmp2 = u.multiply(BigInteger.valueOf(hashSaltPassword));

                  tmp2 = tmp2.add(BigInteger.valueOf(a));

                  S = S.pow(Integer.valueOf(String.valueOf(tmp2)));

                  S = S.mod(BigInteger.valueOf(safePrime));

                  options.add(String.valueOf(S));
                  BigInteger generalSessionKey = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  options.add(String.valueOf(safePrime));
                  BigInteger hashSafePrime = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  options.add(String.valueOf(generator));
                  BigInteger hashGenerator = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  options.add(username);
                  BigInteger hashUsername = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  int xor = (Integer.valueOf(String.valueOf(hashSafePrime))) ^ (Integer.valueOf(String.valueOf(hashGenerator)));

                  options.add(String.valueOf(xor));
                  options.add(String.valueOf(hashGenerator));
                  options.add(String.valueOf(hashUsername));
                  options.add(salt);
                  options.add(String.valueOf(computationalNumber));
                  options.add(String.valueOf(B));
                  options.add(String.valueOf(generalSessionKey));

                  BigInteger clientM = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  output.write(clientM + "\n");
                  output.flush();

                  int serverR = Integer.valueOf(input.readLine());

                  options.add(String.valueOf(computationalNumber));
                  options.add(String.valueOf(clientM));
                  options.add(String.valueOf(generalSessionKey));

                  BigInteger clientR = BigInteger.valueOf(hashFunction(options));
                  options.clear();

                  if (!(BigInteger.valueOf(serverR).equals(clientR))){
                      JOptionPane.showMessageDialog(null,"R client != R server");
                      workClient = false;
                      connection.close();
                      input.close();
                      output.close();
                  }

                  System.out.println("\n" + "Authentication:");
                  System.out.println("Username: " + username);
                  System.out.println("Password: " + password);
                  System.out.println("salt = " + salt);
                  System.out.println("Hash = " + hashSaltPassword);
                  System.out.println("u = " + u);
                  System.out.println("S = " + S);
                  System.out.println("General session key = " + generalSessionKey);
                  System.out.println("Client M = " + clientM);
                  System.out.println("Client R = " + clientR);
                  System.out.println("Server R = " + serverR);
                  System.out.println("Login successful!" + "\n");
              }

        }catch (Exception e){
            JOptionPane.showMessageDialog(null,"Server is not connection!");
            workClient = false;
        }
    }

    class TestActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                if (e.getSource() == connect){
                    if (!workClient) {
                        connection = new Socket("Localhost", 8888);
                        input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                        output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

                        output.write("connect" + "\n");
                        output.flush();

                        workClient = true;
                    }else {
                        JOptionPane.showMessageDialog(null, "Server already connecting!");
                    }
                }

                if (e.getSource() == registrationButton){
                    if (workClient) {
                        username = inputUsername.getText();
                        password = inputPassword.getText();

                        if ((inputUsername.getText().trim().length() == 0) || (inputPassword.getText().trim().length() == 0)) {
                            JOptionPane.showMessageDialog(null, "Input username and password!");
                        } else {
                            inputUsername.setText(null);
                            inputPassword.setText(null);

                            salt = generateRandomString();

                            System.out.println("\n" + "Registration:");
                            System.out.println("Username: " + username);
                            System.out.println("Password: " + password);
                            System.out.println("Salt: " + salt);

                            getRegistrationParameters();

                            sendRegistrationParameters();
                        }
                    }else {
                        JOptionPane.showMessageDialog(null, "Server is not connection!");
                    }
                }

                if (e.getSource() == authenticationButton){
                    if (workClient) {
                        username = inputUsername.getText();
                        password = inputPassword.getText();

                        if ((inputUsername.getText().trim().length() == 0) || (inputPassword.getText().trim().length() == 0)) {
                            JOptionPane.showMessageDialog(null, "Input username and password!");
                        } else {
                            inputUsername.setText(null);
                            inputPassword.setText(null);

                            if(!(usernameList.contains(username))){
                                System.out.println("User is not registered!");
                            }else {
                                int index = usernameList.indexOf(username);
                                generator = generatorList.get(index);
                                safePrime = safePrimeList.get(index);

                                getAuthorizationParameters();

                                sendAuthorizationParameters();

                                checkAuthenticationParameters();
                            }
                        }
                    }else {
                        JOptionPane.showMessageDialog(null, "Server is not connection!");
                    }
                }

                if (e.getSource() == disconnect){
                    if (workClient) {
                        input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                        output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

                        output.write("disconnect" + "\n");
                        output.flush();

                        workClient = false;
                        connection.close();
                        input.close();
                        output.close();
                    }else {
                        JOptionPane.showMessageDialog(null, "Server already disconnecting!");
                    }
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error client system!");
            }
        }
    }

    public static void getRegistrationParameters() throws NoSuchAlgorithmException {
        int q = simpleNumber[(int) (Math.random() * simpleNumber.length)];
        safePrime = 2 * q + 1;

        options.add(salt);
        options.add(password);
        hashSaltPassword = hashFunction(options);
        options.clear();

        boolean check = true;
        while (check) {


            int X = (int) (Math.random() * safePrime) + 1;
            generator = (int) (Math.random() * 1000) + 1;

            BigInteger tmp = new BigInteger(String.valueOf(BigInteger.valueOf(generator)));
            tmp = tmp.pow((int)hashSaltPassword);

            BigInteger mod = tmp.mod(BigInteger.valueOf(safePrime));

            if (mod.equals(BigInteger.valueOf(X))){
                check = false;
            }
        }

        if (!(usernameList.contains(username))) {
            usernameList.add(username);
            generatorList.add(generator);
            safePrimeList.add(safePrime);
        }else {
            System.out.println("Such user is already registered! (" + username + ")" + "\n");
        }

        BigInteger tmp = new BigInteger(String.valueOf(BigInteger.valueOf(generator)));
        tmp = tmp.pow((int)hashSaltPassword);

        BigInteger mod = tmp.mod(BigInteger.valueOf(safePrime));

        passwordVerifier = Integer.valueOf(String.valueOf(mod));

        System.out.println("\n" + "N = " + safePrime);
        System.out.println("Hash = " + hashSaltPassword);
        System.out.println("g = " + generator);
        System.out.println("v = " + passwordVerifier);
    }

    public static void getAuthorizationParameters(){
        a =  (int) (Math.random() * 100);

        BigInteger tmp = new BigInteger(String.valueOf(generator));
        tmp = tmp.pow(a);

        BigInteger mod = tmp.mod(BigInteger.valueOf(safePrime));
        computationalNumber = Integer.valueOf(String.valueOf(mod));

    }

    public static long hashFunction(ArrayList<String> opt) throws NoSuchAlgorithmException {
        String text = "";

        for (String element : opt) {
            text += element;
        }

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(text.getBytes());

        byte byteHash[] = md.digest();

        StringBuffer hashString = new StringBuffer();
        for(byte aByteHash : byteHash){
            String hex = Integer.toHexString(0xFF & aByteHash);
            if (hex.length() == 1){
                hashString.append('0');
            }else {
                hashString.append(hex);
            }
        }


        char[] hashChar = hashString.toString().toCharArray();

        long hashInt;
        long hashIntA = 0;
        long hashIntB = 0;
        long hashIntC =  0;
        long hashIntD = 0;

        for (int element = 0; element < hashChar.length; element++){
            if (hashChar[element] == '0' || hashChar[element] == '1'){
                hashIntA ++;
            }
            if (hashChar[element] == '9' || hashChar[element] == 'a'){
                hashIntB ++;
            }
            if (hashChar[element] == 'f'){
                hashIntC ++;
            }
            if (hashChar[element] == '5' || hashChar[element] == '3'){
                hashIntD ++;
            }
        }

        hashInt = ((int) Math.pow(hashIntA * hashIntB, hashIntC));

        //hashInt = hashInt * hashIntD;

        return hashInt;
    }

    public static String generateRandomString(){
        return UUID.randomUUID().toString().replace("-","");
    }
}