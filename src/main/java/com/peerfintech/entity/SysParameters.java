package com.peerfintech.entity;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

public class SysParameters {
    private Element G_1;//G1是加法群
    private Element G_2;//G2是乘法群

    public Pairing getPairing() {
        return pairing;
    }

    public void setPairing(Pairing pairing) {
        this.pairing = pairing;
    }

    private Pairing pairing;// 双线性映射e
    private Element P;//群G1的生成元
    private Element SK;//主私钥SK
    private Element P_pub;//主公钥
    private Field Z_q;

    public Element getSK() {
        return SK;
    }

    public void setSK(Element SK) {
        this.SK = SK;
    }


    public Field getZ_q() {
        return Z_q;
    }

    public void setZ_q(Field z_q) {
        Z_q = z_q;
    }


    public Element getP_pub() {
        return P_pub;
    }

    public void setP_pub(Element p_pub) {
        P_pub = p_pub;
    }


    public Element getG_1() {
        return G_1;
    }

    public void setG_1(Element g_1) {
        G_1 = g_1;
    }

    public Element getG_2() {
        return G_2;
    }

    public void setG_2(Element g_2) {
        G_2 = g_2;
    }


    //Hash : {0, 1}∗ → G1
    public Element hashFromStringToG1(String str, Pairing pairing) {
        return pairing.getG1().newElement().setFromHash(str.getBytes(), 0, str.length()).getImmutable();
    }

    public Element hashFromBytesToG1(byte[] bytes, Pairing pairing) {
        return pairing.getG1().newElement().setFromHash(bytes, 0, bytes.length).getImmutable();
    }

    //Hash:{0, 1}∗ → Zp
    public Element hashFromStringToZp(String str, Pairing pairing) {
        return pairing.getZr().newElement().setFromHash(str.getBytes(), 0, str.length()).getImmutable();
    }

    public Element hashFromBytesToZp(byte[] bytes, Pairing pairing) {
        return pairing.getZr().newElement().setFromHash(bytes, 0, bytes.length).getImmutable();
    }

    public Element getP() {
        return P;
    }

    public void setP(Element p) {
        P = p;
    }

    //{0, 1}∗ → {0,1}e


}
