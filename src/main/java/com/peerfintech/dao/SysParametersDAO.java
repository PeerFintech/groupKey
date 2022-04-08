package com.peerfintech.dao;

import com.peerfintech.entity.SysParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public class SysParametersDAO {
    /*
    函数：genSysPara
    作用：系统参数初始化
    输入：
    输出：SysParameters
     */
    public SysParameters genSysPara() throws IOException {
        SysParameters syspara = new SysParameters();
        int rBit=160;
        int qBit=512;
        TypeACurveGenerator pg = new TypeACurveGenerator(rBit, qBit);
        PairingParameters typeAParams = pg.generate();
        System.out.println(typeAParams);
        //将生成的参数写入文件
        File file =new File("a.properties");
        Writer out =new FileWriter(file);
        out.write(String.valueOf(typeAParams));
        out.close();

        //从文件a.properties中读取参数初始化双线性群
        Pairing pairing;
        pairing = PairingFactory.getPairing("a.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        checkSymmetric(pairing); //判断配对是否为对称配对，不对称则输出错误信息
        syspara.setPairing(pairing);
        System.out.println("双线性对pairing："+syspara.getPairing());
        syspara.setZ_q(pairing.getZr());

        //得到G1的生成元
        Field G1 = pairing.getG1();
        Element P = G1.newRandomElement().getImmutable();
        syspara.setP(P);
        Element SK = syspara.getZ_q().newRandomElement().getImmutable();//私钥SK 2020-12-29 revised
        syspara.setSK(SK);
        System.out.println("主密钥SK："+SK);
        System.out.println("主密钥SK："+syspara.getSK());
        System.out.println("群G1的生成元P："+syspara.getP());
        System.out.println("群G1的生成元P："+P);
        //主公钥
        syspara.setP_pub(P.mulZn(SK));
        System.out.println("主公钥P_pub："+syspara.getP_pub());
        return syspara;
    }

    public void checkSymmetric(Pairing pairing) {
        if (!pairing.isSymmetric()) {
            throw new RuntimeException("密钥不对称!");
        }
    }
}
