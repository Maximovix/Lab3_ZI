package com.company;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.UUID;

public class Client extends JFrame implements Runnable {
    private static Socket connection;
    private static BufferedReader input;
    private static BufferedWriter output;
    private static boolean workClient = true;

    static JPanel panelUsername, panelPassword, panelButton;
    static JLabel labelUsername, labelPassword;
    static JTextField inputUsername;
    static JPasswordField inputPassword;
    static JButton  authenticationButton, registrationButton, disconnect;

    static Toolkit kit = Toolkit.getDefaultToolkit();
    static Dimension screenSize = kit.getScreenSize();
    TestActionListener testActionListener = new TestActionListener();
    static Image image = kit.getImage("Matrix.jpg");

    private static int lx = screenSize.width;
    private static int ly = screenSize.height;

    private static ArrayList<String> options = new ArrayList<>();
    private static int[] simpleNumber = {3,5,7,11,13,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101};
    private static final int k = 3;
    private static int a;
    private static String username;
    private static String password;
    private static String salt;
    private static int passwordVerifier;
    private static int safePrime;
    private static int hashSaltPassword;
    private static int generator;
    private static int computationalNumber;

    public Client(String name) throws IOException {
        super(name);
        createGUI();

        connection = new Socket("Localhost", 8888);
        input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

    }

    public void createGUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        setBounds(lx / 2, ly / 2, 400, 150);
        setResizable(false);

        setIconImage(image);

        panelUsername = new JPanel();
        panelPassword = new JPanel();
        panelButton = new JPanel();

        labelUsername = new JLabel("login          ");
        labelPassword = new JLabel("password");

        inputUsername = new JTextField(10);
        inputPassword = new JPasswordField(10);

        registrationButton = new JButton("Registration");
        authenticationButton = new JButton("Authentication");
        disconnect = new JButton("Disconnect");

        panelUsername.add(labelUsername);
        panelUsername.add(inputUsername);

        panelPassword.add(labelPassword);
        panelPassword.add(inputPassword);

        panelButton.add(registrationButton);
        panelButton.add(authenticationButton);
        panelButton.add(disconnect);

        getContentPane().add(BorderLayout.NORTH, panelUsername);
        getContentPane().add(BorderLayout.CENTER, panelPassword);
        getContentPane().add(BorderLayout.SOUTH, panelButton);

        setVisible(true);

        registrationButton.addActionListener(testActionListener);
        authenticationButton.addActionListener(testActionListener);
        disconnect.addActionListener(testActionListener);
    }

    @Override
    public void run() {
        try {
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

            while (workClient){
                String work = input.readLine();

                if (work.equals("B")){
                   int B = Integer.valueOf(input.readLine());

                   salt = input.readLine();

                   if (B != 0){
                       options.add(String.valueOf(computationalNumber));
                       options.add(String.valueOf(B));
                       int u = hashFunction(options);
                       options.clear();

                       options.add(salt);
                       options.add(password);
                       hashSaltPassword = hashFunction(options);
                       options.clear();

                       int S = ((int) Math.pow((B - k * (((int) Math.pow(generator,hashSaltPassword)) % safePrime)),a + u * hashSaltPassword)) % safePrime;

                       options.add(String.valueOf(S));
                       int generalSessionKey = hashFunction(options);
                       options.clear();

                       options.add(String.valueOf(safePrime));
                       int hashSafePrime = hashFunction(options);
                       options.clear();

                       options.add(String.valueOf(generator));
                       int hashGenerator = hashFunction(options);
                       options.clear();

                       options.add(username);
                       int hashUsername = hashFunction(options);
                       options.clear();

                       int xor = hashSafePrime ^ hashGenerator;

                       options.add(String.valueOf(xor));
                       options.add(String.valueOf(hashUsername));
                       options.add(salt);
                       options.add(String.valueOf(computationalNumber));
                       options.add(String.valueOf(B));
                       options.add(String.valueOf(generalSessionKey));

                       int clientM = hashFunction(options);
                       options.clear();

                       output.write(clientM + "\n");
                       output.flush();

                       int serverR = Integer.valueOf(input.readLine());

                       options.add(String.valueOf(computationalNumber));
                       options.add(String.valueOf(clientM));
                       options.add(String.valueOf(generalSessionKey));

                       int clientR = hashFunction(options);
                       options.clear();



                       System.out.println("B = " + B);
                       System.out.println("salt = " + salt);
                       System.out.println("u = " + u);
                       System.out.println("S = " + S);
                       System.out.println("General session key = " + generalSessionKey);
                       System.out.println("M = " + clientM);
                       System.out.println("Client R = " + clientR);
                       System.out.println("Server R = " + serverR);

                       if (clientR != serverR){
                           input.close();
                           output.close();
                           connection.close();
                           workClient = false;
                       }
                   }else {
                       workClient = false;
                       connection.close();
                       input.close();
                       output.close();
                   }
                }
            }
        }catch (Exception e) {
            try {
                salt = input.readLine();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            System.err.println("Ошибка обращения");
        }
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
        }
    }

    public void sendAuthenticationParameters(){
        try{
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

            output.write("authentication" + "\n");
            output.flush();

            output.write(username + "\n");
            output.flush();

            output.write(computationalNumber + "\n");
            output.flush();
        }catch (Exception e){
            JOptionPane.showMessageDialog(null,"Server is not connection!");
        }
    }

    class TestActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                if (e.getSource() == registrationButton){
                    username = inputUsername.getText();
                    password = inputPassword.getText();

                    if ((inputUsername.getText().trim().length() == 0) || (inputPassword.getText().trim().length() == 0)) {
                        JOptionPane.showMessageDialog(null, "Input username and password!");
                    }else {
                        inputUsername.setText(null);
                        inputPassword.setText(null);

                        salt = generateRandomString();

                        getRegistrationParameters();

                        sendRegistrationParameters();

                        System.out.println("\n" + "Username: " + username);
                        System.out.println("Password: " + password);
                        System.out.println("Salt: " + salt);
                    }
                }

                if (e.getSource() == authenticationButton){
                    username = inputUsername.getText();
                    password = inputPassword.getText();

                    if ((inputUsername.getText().trim().length() == 0) || (inputPassword.getText().trim().length() == 0)) {
                        JOptionPane.showMessageDialog(null, "Input username and password!");
                    }else {
                        inputUsername.setText(null);
                        inputPassword.setText(null);

                        getAuthenticationParameters();

                        sendAuthenticationParameters();
                    }
                }

                if (e.getSource() == disconnect){
                    workClient = false;
                    connection.close();
                    input.close();
                    output.close();
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

            int X = (int) (Math.random() * safePrime);
            generator = (int) (Math.random() * 100);

            if (Math.pow(generator,hashSaltPassword) % safePrime == X) {
                    check = false;
            }
        }

        passwordVerifier = ((int)Math.pow(generator,hashSaltPassword)) % safePrime;

        System.out.println("\n" + "N = " + safePrime);
        System.out.println("x = " + hashSaltPassword);
        System.out.println("g = " + generator);
        System.out.println("v = " + passwordVerifier);
    }

    public static void getAuthenticationParameters(){
        a =  (int) (Math.random() * 100);
        computationalNumber = ((int) (Math.pow(generator,a))) % safePrime;

    }

    public static int hashFunction(ArrayList<String> opt) throws NoSuchAlgorithmException {
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

        int hashInt = 0;

        for (int element = 0; element < hashChar.length; element++){
            if (hashChar[element] == '0' || hashChar[element] == '1'){
                hashInt++;
            }
        }

        return hashInt;
    }

    public static String generateRandomString(){
        return UUID.randomUUID().toString().replace("-","");
    }
}