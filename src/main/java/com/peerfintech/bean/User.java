package com.peerfintech.bean;

import it.unisa.dia.gas.jpbc.Element;

public class User {//用户的公私钥对
    private Element upk_1;//Q
    private Element upk_2;//P
    private Element usk_1;//D
    private Element usk_2;//x
    private byte[] id;
    private int i;//记录在用户序列中是第几个用户
    private Element s;//私有保存的消息值
    private Element h;
    private Element T;
    private Element groupEncryptionKey_R;//群组加密密钥
    private Element groupEncryptionKey_O;
    private Element groupDecryptionKey;//群组解密密钥
    private Element r;//随机数r

    public Element getR() {
        return r;
    }

    public void setR(Element r) {
        this.r = r;
    }



    public Element getGroupEncryptionKey_R() {
        return groupEncryptionKey_R;
    }

    public void setGroupEncryptionKey_R(Element groupEncryptionKey_R) {
        this.groupEncryptionKey_R = groupEncryptionKey_R;
    }

    public Element getGroupEncryptionKey_O() {
        return groupEncryptionKey_O;
    }

    public void setGroupEncryptionKey_O(Element groupEncryptionKey_O) {
        this.groupEncryptionKey_O = groupEncryptionKey_O;
    }

    public Element getGroupDecryptionKey() {
        return groupDecryptionKey;
    }

    public void setGroupDecryptionKey(Element groupDecryptionKey) {
        this.groupDecryptionKey = groupDecryptionKey;
    }



    public Element getT() {
        return T;
    }

    public void setT(Element t) {
        T = t;
    }



    public Element getH() {
        return h;
    }

    public void setH(Element h) {
        this.h = h;
    }



    public int getI() {
        return i;
    }

    public void setI(int i) {
        this.i = i;
    }



    public Element getS() {
        return s;
    }

    public void setS(Element s) {
        this.s = s;
    }



    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }



    public Element getUpk_1() {
        return upk_1;
    }

    public void setUpk_1(Element upk_1) {
        this.upk_1 = upk_1;
    }

    public Element getUpk_2() {
        return upk_2;
    }

    public void setUpk_2(Element upk_2) {
        this.upk_2 = upk_2;
    }

    public Element getUsk_1() {
        return usk_1;
    }

    public void setUsk_1(Element usk_1) {
        this.usk_1 = usk_1;
    }

    public Element getUsk_2() {
        return usk_2;
    }

    public void setUsk_2(Element usk_2) {
        this.usk_2 = usk_2;
    }



}
