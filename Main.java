package com.company;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
       new Thread( new Server("Server")).start();
       new Thread( new Client("Client")).start();
    }
}
