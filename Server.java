package com.company;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.UUID;

public class Server extends JFrame implements Runnable {
    private static Socket connection;
    private static ServerSocket server;
    private static BufferedReader input;
    private static BufferedWriter output;
    private static boolean workServer = true;

    static JPanel panel;
    static JTextArea textArea;
    static JScrollPane scroll;
    static Toolkit kit = Toolkit.getDefaultToolkit();
    static Dimension screenSize = kit.getScreenSize();
    TestActionListener testActionListener = new TestActionListener();
    static Image image = kit.getImage("Matrix.jpg");

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

    public Server(String name) throws IOException {
        super(name);
        createGUI();
        server = new ServerSocket(8888);
        textArea.append("Server is running!" + "\n");
        connection = server.accept();
    }

    public void createGUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        setBounds(lx / 3, ly / 30, 720, 430);
        setResizable(false);

        setIconImage(image);

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
        try {
            input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            output = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
            int count = 1;

            while (workServer){
                String work = input.readLine();

                if (work.equals("registration")) {
                    username = input.readLine();
                    salt = input.readLine();
                    passwordVerifier = Integer.valueOf(input.readLine());
                    generator = Integer.valueOf(input.readLine());
                    safePrime = Integer.valueOf(input.readLine());

                    if (usernameList.contains(username)){
                        textArea.append("Such user is already registered! (" + username + ")" + "\n" + "\n");
                    }else {
                        usernameList.add(username);
                        saltList.add(salt);
                        passwordVerifierList.add(passwordVerifier);
                        generatorList.add(generator);
                        safePrimeList.add(safePrime);

                        textArea.append("Registration User" + "\n");
                        textArea.append("Username: " + username + "\n");
                        textArea.append("Salt: " + salt + "\n");
                        textArea.append("Password verifier = " + passwordVerifier + "\n");
                        textArea.append("Generator: " + generator + "\n");
                        textArea.append("Safe Prime = " + safePrime + "\n" + "\n");
                    }
                }
                if(work.equals("authentication")){
                    username = input.readLine();
                    int computationalNumber = Integer.valueOf(input.readLine());

                    if((computationalNumber == 0) || !(usernameList.contains(username))) {
                        JOptionPane.showMessageDialog(null,"This user does not exist!");
                        workServer = false;
                        connection.close();
                        input.close();
                        output.close();
                    }else{
                        int index = usernameList.indexOf(username);

                        salt = saltList.get(index);
                        passwordVerifier = passwordVerifierList.get(index);
                        generator = generatorList.get(index);
                        safePrime = safePrimeList.get(index);

                        int b =  (int) (Math.random() * 100);

                        int B = (k * passwordVerifier + (((int)Math.pow(generator,b)) % safePrime)) % safePrime;


                        if (count == 1) {
                            output.write("B" + "\n");
                            output.flush();

                            output.write(B + "\n");
                            output.flush();

                            output.write(B + "\n");
                            output.flush();

                            output.write(salt + "\n");
                            output.flush();

                            int clientM = Integer.valueOf(input.readLine());

                            options.add(String.valueOf(computationalNumber));
                            options.add(String.valueOf(B));
                            int u = hashFunction(options);
                            options.clear();

                            int S = ((int) Math.pow(computationalNumber * (((int) Math.pow(passwordVerifier,u)) % safePrime),b)) % safePrime;

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

                            int serverM = hashFunction(options);
                            options.clear();

                            System.out.println("u = " + u);
                            System.out.println("S = " + S);
                            System.out.println("General session key = " + generalSessionKey);
                            System.out.println("Client M = " + clientM);
                            System.out.println("Server M = " + serverM);
                            count++;
                        }else {
                            output.write("B" + "\n");
                            output.flush();

                            output.write(B + "\n");
                            output.flush();

                            output.write(salt + "\n");
                            output.flush();

                            int clientM = Integer.valueOf(input.readLine());

                            options.add(String.valueOf(computationalNumber));
                            options.add(String.valueOf(B));
                            int u = hashFunction(options);
                            options.clear();

                            int S = ((int) Math.pow(computationalNumber * (((int) Math.pow(passwordVerifier,u)) % safePrime),b)) % safePrime;

                            options.add(String.valueOf(S));

                            int generalSessionKey = hashFunction(options);

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

                            int serverM = hashFunction(options);
                            options.clear();

                            if (clientM != serverM){
                                input.close();
                                output.close();
                                connection.close();
                                workServer = false;
                            }else {
                                options.add(String.valueOf(computationalNumber));
                                options.add(String.valueOf(serverM));
                                options.add(String.valueOf(generalSessionKey));

                                int serverR = hashFunction(options);
                                options.clear();

                                output.write(serverR + "\n");
                                output.flush();
                            }

                            System.out.println("u = " + u);
                            System.out.println("S = " + S);
                            System.out.println("General session key = " + generalSessionKey);
                            System.out.println("Client M = " + clientM);
                            System.out.println("Server M = " + serverM);
                        }

                        textArea.append("Authentication User" + "\n");
                        textArea.append("Username: " + username + "\n");
                        textArea.append("A = " + computationalNumber + "\n");
                        textArea.append("B = " + B + "\n");
                        textArea.append("Salt: " + salt + "\n");
                        textArea.append("Password verifier = " + passwordVerifier + "\n");
                        textArea.append("Generator: " + generator + "\n");
                        textArea.append("Safe Prime = " + safePrime + "\n" + "\n");
                    }
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Client is not connection!");
        }
    }

    class TestActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error system!");
            }
        }
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

