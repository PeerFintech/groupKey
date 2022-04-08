package com.peerfintech.bean;

import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;

public class Ciphertext {
    public Element getC1() {
        return c1;
    }

    public void setC1(Element c1) {
        this.c1 = c1;
    }

    public Element getC2() {
        return c2;
    }

    public void setC2(Element c2) {
        this.c2 = c2;
    }


    private Element c1;
    private Element c2;

    public byte[] getC3() {
        return c3;
    }

    public void setC3(byte[] c3) {
        this.c3 = c3;
    }

    private byte[] c3;

    public static String hash_f_key(String data) {
        try {
            MessageDigest hasher = MessageDigest.getInstance("SHA-512");
            byte[] result = hasher.digest(data.getBytes());
            return result.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    public static byte[] hash_f_key2(byte[] data) {
        try {
            MessageDigest hasher = MessageDigest.getInstance("SHA-512");
            byte[] result = hasher.digest(data);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



}
