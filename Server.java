package com.company;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Server extends JFrame implements Runnable {
    private static Socket connection;
    private static ServerSocket server;
    private static BufferedReader input;
    private static BufferedWriter output;
    private static boolean connectionClient = false;
    private static boolean workServer = true;

    static JPanel panel;
    static JTextArea textArea;
    static JScrollPane scroll;
    static Toolkit kit = Toolkit.getDefaultToolkit();
    static Dimension screenSize = kit.getScreenSize();

    private static int lx = screenSize.width;
    private static int ly = screenSize.height;

    private static ArrayList<String> usernameList = new ArrayList<>();
    private static ArrayList<String> saltList = new ArrayList<>();
    private static ArrayList<Integer> passwordVerifierList = new ArrayList<>();
    private static ArrayList<Integer> generatorList = new ArrayList<>();
    private static ArrayList<Integer> safePrimeList = new ArrayList<>();
    private static ArrayList<String> options = new ArrayList<>();
    private static final int k = 3;
    private static String username;
    private static String salt;
    private static int passwordVerifier;
    private static int generator;
    private static int safePrime;
    private static int computationalNumber;

    public Server(String name) throws IOException {
        super(name);
        createGUI();
        server = new ServerSocket(8888);
        textArea.append("Server is running!" + "\n");
    }

    public void createGUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        setBounds(lx / 3, ly / 30, 720, 430);
        setResizable(false);

        panel = new JPanel();

        panel.setBorder(new TitledBorder(new EtchedBorder(), "Server Output"));
        textArea = new JTextArea(20, 60);
        scroll = new JScrollPane(textArea);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scroll);

        getContentPane().add(BorderLayout.CENTER, panel);

        setVisible(true);
    }

    @Override
    public void run() {
        while (workServer) {
            try {
                connection = server.accept();
                connectionClient = true;
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, " Client is not found!");
            }

            try {
                input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));

                while (connectionClient) {
                    String work = input.readLine();

                    if (work.equals("connect")) {
                        textArea.append("\n" + "Connecting with Client!" + "\n");
                    }

                    if (work.equals("registration")) {
                        username = input.readLine();
                        salt = input.readLine();
                        passwordVerifier = Integer.valueOf(input.readLine());
                        generator = Integer.valueOf(input.readLine());
                        safePrime = Integer.valueOf(input.readLine());

                        if (usernameList.contains(username)) {
                            textArea.append("Such user is already registered! (" + username + ")" + "\n" + "\n");
                        } else {
                            usernameList.add(username);
                            saltList.add(salt);
                            passwordVerifierList.add(passwordVerifier);
                            generatorList.add(generator);
                            safePrimeList.add(safePrime);

                            textArea.append("\n" + "Registration Client:" + "\n");
                            textArea.append("Username: " + username + "\n");
                            textArea.append("Salt: " + salt + "\n");
                            textArea.append("Password verifier = " + passwordVerifier + "\n");
                            textArea.append("Generator: " + generator + "\n");
                            textArea.append("Safe Prime = " + safePrime + "\n" + "\n");
                        }
                    }

                    if (work.equals("authorization")) {
                        username = input.readLine();
                        computationalNumber = Integer.valueOf(input.readLine());

                        textArea.append("\n" + "Authorization Client:" + "\n");
                        textArea.append("Username: " + username + "\n");
                        textArea.append("A = " + computationalNumber + "\n");

                        if (!(usernameList.contains(username))) {
                            JOptionPane.showMessageDialog(null, "This user does not exist!");
                            if (computationalNumber == 0) {
                                connectionClient = false;
                                connection.close();
                                input.close();
                                output.close();
                            }
                        }
                    }

                    if (work.equals("authentication")) {
                        int index = usernameList.indexOf(username);

                        salt = saltList.get(index);
                        passwordVerifier = passwordVerifierList.get(index);
                        generator = generatorList.get(index);
                        safePrime = safePrimeList.get(index);

                        int b = ((int) (Math.random() * 100));

                        BigInteger tmp = new BigInteger(String.valueOf(generator));

                        tmp = tmp.pow(b);

                        tmp = tmp.mod(BigInteger.valueOf(safePrime));

                        BigInteger B = new BigInteger(String.valueOf(k * passwordVerifier));

                        B = B.add(tmp);

                        B = B.mod(BigInteger.valueOf(safePrime));

                        output.write(B + "\n");
                        output.flush();

                        output.write(salt + "\n");
                        output.flush();

                        options.add(String.valueOf(computationalNumber));
                        options.add(String.valueOf(B));
                        BigInteger u = BigInteger.valueOf(hashFunction(options));
                        options.clear();

                        BigInteger S = new BigInteger(String.valueOf(passwordVerifier));

                        S = S.pow(Integer.valueOf(String.valueOf(u)));

                        S = S.mod(BigInteger.valueOf(safePrime));

                        S = S.multiply(BigInteger.valueOf(computationalNumber));

                        S = S.pow(b);

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

                        BigInteger serverM = BigInteger.valueOf(hashFunction(options));
                        options.clear();

                        int clientM = Integer.valueOf(input.readLine());

                        if (!(BigInteger.valueOf(clientM).equals(serverM))) {
                            connectionClient = false;
                            connection.close();
                            input.close();
                            output.close();
                            textArea.append("\n" + "Invalid password" + "\n");
                            JOptionPane.showMessageDialog(null, "Invalid password entered!");
                        } else {
                            options.add(String.valueOf(computationalNumber));
                            options.add(String.valueOf(serverM));
                            options.add(String.valueOf(generalSessionKey));

                            BigInteger serverR = BigInteger.valueOf(hashFunction(options));
                            options.clear();

                            output.write(serverR + "\n");
                            output.flush();

                            textArea.append("\n" + "Authentication Client:" + "\n");
                            textArea.append("Username: " + username + "\n");
                            textArea.append("A = " + computationalNumber + "\n");
                            textArea.append("B = " + B + "\n");
                            textArea.append("Salt: " + salt + "\n");
                            textArea.append("Password verifier = " + passwordVerifier + "\n");
                            textArea.append("Generator: " + generator + "\n");
                            textArea.append("Safe Prime = " + safePrime + "\n");
                            textArea.append("u = " + u + "\n");
                            textArea.append("S = " + S + "\n");
                            textArea.append("General session key = " + generalSessionKey + "\n");
                            textArea.append("Client M = " + clientM + "\n");
                            textArea.append("Server M = " + serverM + "\n");
                            textArea.append("Server R = " + serverR + "\n");
                            textArea.append("Login successful!" + "\n" + "\n");
                        }
                    }
                    if (work.equals("disconnect")) {
                        textArea.append("\n" + "Disconnecting with Client!" + "\n");
                        connectionClient = false;
                    }
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Client is not connection!");
            }
        }
        JOptionPane.showMessageDialog(null, "Server is not working!");
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
}

