package com.peerfintech.dao;

import com.peerfintech.entity.Ciphertext;
import com.peerfintech.entity.SysParameters;
import com.peerfintech.entity.User;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.io.*;
import java.util.ArrayList;
import java.util.Random;

public class UserDAO {
    /*
    函数：generateUserListKey
    作用：用户组的公私钥生成
    输入：参与密钥协商的群组成员数量 n
    输出：已生成好公私钥对的userlist ArrayList<User>
     */
    public ArrayList<User> generateUserListKey(int n, SysParameters syspara) {
        System.out.println("generateUserListKey");
        ArrayList<User> userlist = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            User u = new User();
            u = generateOneUserKey(u, syspara);
            u.setI(i + 1);
            userlist.add(u);
            System.out.println("第几位用户：" + u.getI());
            System.out.println("PK1：" + u.getUpk_1());
            System.out.println("PK2：" + u.getUpk_2());
            System.out.println("SK1：" + u.getUsk_1());
            System.out.println("SK2：" + u.getUsk_2());
        }
        return userlist;
    }

    /*
    函数：generateOneUserKey
    作用：生成用户的公私钥对
    输入：
    输出：
     */

    public User generateOneUserKey(User u, SysParameters syspara) {

        System.out.println("generateOneUserKey");
        byte[] randomBytes = chooseUserIdentity();//2021-1-5 xysong 后续用户的ID值可以通过区块链网络提供
        u.setId(randomBytes);//设置该用户的ID值
        Element upk_1 = syspara.hashFromBytesToG1(randomBytes, syspara.getPairing());
        u.setUpk_1(upk_1);//设置部分公钥

        Element D_i = upk_1.mulZn(syspara.getSK()).getImmutable();//设置该部分对应的私钥
        u.setUsk_1(D_i);


        //计算另一部分私钥与公钥
        Element x_i = syspara.getZ_q().newRandomElement().getImmutable();// 2020-12-29 revised
        u.setUsk_2(x_i);
        Element upk_2 = syspara.getP().mulZn(x_i).getImmutable();
        u.setUpk_2(upk_2);

        return u;

    }

    /*
    函数：chooseUserIdentity
    作用：用户随机选择一个身份信息
    输入：
    输出：32位的串
     */
    public byte[] chooseUserIdentity() {
        //用户随机选择一个身份信息
        byte randomBytes[] = new byte[32];//随机选择一个32位长度的串
        Random rand = new Random();
        for (int i = 0; i < 32; i++) {
            rand.nextBytes(randomBytes);
        }
        return randomBytes;
    }

    /*
    函数：UserGenerateBroadcastInformation
    作用：用户u_i生成广播信息
    输入：会话状态信息theta是byte[]类型，n是用户数量
    输出：
     */
    public ArrayList<Element> UserGenerateBroadcastInformation(User u_i, SysParameters syspara, byte[] theta, int n) {
        //选择随机数ri
        System.out.println("第几个用户：i=" + u_i.getI());
        Element r_i = syspara.getZ_q().newRandomElement().getImmutable();
        u_i.setR(r_i);//绑定随机数
        System.out.println("r_i的值：" + r_i);

        //计算Ri
        Element R_i = syspara.getP().mulZn(r_i);
        System.out.println("R_i的值：" + R_i);
        System.out.println("根据会话状态信息和H2计算V");
        //根据会话状态信息和H2计算V
        Element V = syspara.hashFromBytesToG1(theta, syspara.getPairing()).getImmutable();
        System.out.println("V1:" + V);

        //字符串拼接
        StringBuilder sbe = new StringBuilder();
        sbe.append(theta).append(u_i.getId()).append(u_i.getUpk_2()).append(R_i);
        Element h_i = syspara.hashFromStringToZp(sbe.toString(), syspara.getPairing());

        u_i.setH(h_i);//将h_i的信息绑定到用户u上
        Element T[] = new Element[n];
        ArrayList<Element> message_i = new ArrayList<>();
        message_i.add(R_i);

        //u_i为所有用户计算T_j
        Element c1 = syspara.getP_pub().mulZn(h_i);
        Element c2 = c1.add(V);
        Element temp2 = c2.mulZn(u_i.getUsk_2());
        for (int j = 1; j <= n; j++) {
            StringBuilder sbe2 = new StringBuilder();
            sbe2.append(theta).append(j);
            T[j - 1] = syspara.hashFromStringToG1(sbe2.toString(), syspara.getPairing());
            Element temp1 = (u_i.getUsk_1()).add(T[j - 1].mulZn(r_i));
            if (u_i.getI() != j) {
                message_i.add(temp1.add(temp2));
            } else {
                u_i.setS(temp1.add(temp2));
            }
        }
        u_i.setT(T[u_i.getI() - 1]);//将对应的T_i值绑定
        System.out.println("message_i:" + message_i.size());

        return message_i;
    }


    /*
    函数：keyGenerationMatrix
    作用：密钥生成矩阵的形成
    输入：n指的是参与协商的用户数
    输出：
     */
    public Element[][] keyGenerationMatrix(int n, SysParameters syspara, byte[] theta, ArrayList<User> userlist) {
        Element[][] metrix = new Element[n][n + 1];
        System.out.println("UserdDAO: userlist:" + userlist.size());
        for (int i = 0; i < n; i++) {
            User u = userlist.get(i);//得到列表中的一位用户
            ArrayList<Element> message = UserGenerateBroadcastInformation(u, syspara, theta, n);//得到广播的消息
            System.out.println("message:" + message.size());
            metrix[i][0] = message.get(0).getImmutable();
            message.remove(0);

            for (int j = 1; j <= n; j++) {
                if (j != i + 1) {
                    metrix[i][j] = message.get(0).getImmutable();
                    message.remove(0);
                    //System.out.println("2222message:"+message.size());
                } else {
                    metrix[i][j] = null;
                }

            }
        }

        return metrix;

    }



    /*
    函数：groupEncryptionKeyGeneration
    作用：群组加密密钥生成
    输入：输入的内容是密钥生成矩阵
    输出：
     */

    public void groupEncryptionKeyGeneration(User u, Element[][] metrix, SysParameters syspara, ArrayList<User> ulist, byte[] theta) {
        //消息的完整性验证
        Pairing pairing = syspara.getPairing();
        //赋初值
        Element Q_sum = ulist.get(0).getUpk_1().getImmutable();
        Element P_sum = ulist.get(0).getUpk_2().getImmutable();
        Element HP_sum = P_sum.mulZn(ulist.get(0).getH()).getImmutable();
        Element R_sum = metrix[0][0].getImmutable();
        Element S_sum = u.getS().getImmutable();
        System.out.println("u.s:" + u.getS());
        Element V = syspara.hashFromBytesToG1(theta, syspara.getPairing()).duplicate();
        System.out.println("V2:" + V);
        int n = ulist.size(); //参与密钥协商的用户数
        for (int i = 1; i < n; i++) {
            System.out.println("群组密钥生成中第几个用户：" + i);
            Element Q_i = ulist.get(i).getUpk_1().getImmutable();
            //System.out.println("Q_i:"+Q_i);
            Element P_i = ulist.get(i).getUpk_2().getImmutable();
            Element HP_i = P_i.mulZn(ulist.get(i).getH()).getImmutable();
            Element R_i = metrix[i][0].getImmutable();

            Q_sum = Q_sum.add(Q_i).getImmutable();
            P_sum = P_sum.add(P_i).getImmutable();
            HP_sum = HP_sum.add(HP_i.getImmutable());
            R_sum = R_sum.add(R_i.getImmutable());
        }


        for (int j = 0; j < n; j++) {
            for (int k = 0; k <= n; k++) {
                if ((k == u.getI()) && (k != j + 1)) {
                    S_sum = S_sum.add(metrix[j][k]);
                }
            }
        }

        Element e_left = pairing.pairing(S_sum, syspara.getP());
        Element e1_right = pairing.pairing((Q_sum.add(HP_sum)), syspara.getP_pub());
        Element e2_right = pairing.pairing(P_sum, V);
        System.out.println("e1_right:" + e1_right);
        System.out.println("e2_right:" + e2_right);
        Element e3_right = pairing.pairing(u.getT(), R_sum);
        Element e_right = (e1_right.getImmutable().mul(e2_right.getImmutable())).mul(e3_right.getImmutable());
        if (e_left.equals(e_right)) {
            System.out.println("认证通过，公开消息未被篡改");
            u.setGroupEncryptionKey_R(R_sum);
            Element Omega = e1_right.mul(e2_right).duplicate();
            u.setGroupEncryptionKey_O(Omega);
            u.setGroupDecryptionKey(S_sum);
        } else {
            System.out.println("认证未通过");
        }

    }



    public Ciphertext encryptMessage(Element C1, Element C2, Element t_omega, byte[] m) throws IOException {
        Ciphertext c = new Ciphertext();

        byte[] slice_t_omega_1 = subByte(t_omega.toBytes(), 0, 64);
        byte[] slice_t_omega_2 = subByte(t_omega.toBytes(), 64, 64);
        byte[] tmp_h5 = byteMerger(sha512(slice_t_omega_1), sha512(slice_t_omega_2));

        // 比较message长度
        // 如果是针对超过128bit的加密信息
        byte[] C3;
        if (m.length >= 128) {
            C3 = XORForLong(tmp_h5, m);
        } else {
            C3 = XORForShort(tmp_h5, m);
        }

        c.setC1(C1);
        c.setC2(C2);
        c.setC3(C3);
        return c;
    }

    public byte[] decryptMessage(Element C1, Element C2,Element T,Element SKey, byte[] C3) {
        Pairing pairing = PairingFactory.getPairing("a.properties");
        Element t1 = pairing.pairing(SKey, C1).getImmutable();
        Element t2 = pairing.pairing(T, C2).getImmutable();
        Element t_mul = t1.mul(t2);

        byte[] slice_t_mul_1 = subByte(t_mul.toBytes(), 0, 64);
        byte[] slice_t_mul_2 = subByte(t_mul.toBytes(), 64, 64);

        byte[] tmp = byteMerger(sha512(slice_t_mul_1), sha512(slice_t_mul_2));

        byte[] message;
        if (C3.length >= 128) {
            message = XORForLong(C3, tmp);
        } else {
            message = XORForShort(C3, tmp);
        }
        return message;
    }


    public byte[] subByte(byte[] b, int off, int length) {
        byte[] b1 = new byte[length];
        System.arraycopy(b, off, b1, 0, length);
        return b1;
    }

    public byte[] sha512(byte[] data) {
        SHA512Digest dgst = new SHA512Digest();
        dgst.reset();
        dgst.update(data, 0, data.length);
        int digestSize = dgst.getDigestSize();
        byte[] hash = new byte[digestSize];
        dgst.doFinal(hash, 0);
        return hash;
    }


    public byte[] byteMerger(byte[] byte_1, byte[] byte_2) {
        byte[] byte_3 = new byte[byte_1.length + byte_2.length];
        System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);
        System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);
        return byte_3;
    }

    public byte[] XORForLong(byte[] a, byte[] b) {
        byte longbytes[], shortbytes[];
        if (a.length >= b.length) {
            longbytes = a;
            shortbytes = b;
        } else {
            longbytes = b;
            shortbytes = a;
        }
        byte xorstr[] = new byte[longbytes.length];
        int len = shortbytes.length;
        //让短的byte[]循环
        for (int i = 0; i < longbytes.length; i++) {
            xorstr[i] = (byte) (shortbytes[i % len] ^ longbytes[i]);
        }

        return xorstr;
    }

    public byte[] XORForShort(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
        }
        return result;
    }


    //byte数组进行sha 256
    public byte[] sha256(byte[] data) {
        SHA256Digest dgst = new SHA256Digest();
        dgst.reset();
        dgst.update(data, 0, data.length);
        int digestSize = dgst.getDigestSize();
        byte[] hash = new byte[digestSize];
        dgst.doFinal(hash, 0);
        return hash;
    }
}
