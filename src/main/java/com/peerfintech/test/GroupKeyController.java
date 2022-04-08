package com.peerfintech.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.peerfintech.dao.SysParametersDAO;
import com.peerfintech.dao.UserDAO;
import com.peerfintech.entity.Ciphertext;
import com.peerfintech.entity.SysParameters;
import com.peerfintech.entity.User;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.compress.utils.Lists;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
public class GroupKeyController {
    @RequestMapping("gro/creat")
    @ResponseBody
    public String invoke(@RequestBody Map<String, Object> param) {
        try {
            int n = Integer.valueOf(String.valueOf(param.get("n")));
            JSONObject object = new JSONObject();

            System.out.println("test begin");

            UserDAO udao = new UserDAO();

            //int n = 3;//n指的是参与群组密钥协商的用户
            SysParametersDAO sysdao = new SysParametersDAO();
            //生成系统参数
            System.out.println("------生成系统参数 begin------");
            SysParameters syspara = sysdao.genSysPara();
            System.out.println("------生成系统参数 end------");

            //会话状态信息
            System.out.println("会话状态信息：");
            byte[] theta = {0, 1, 1, 0};//替换会话状态信息为固定值

            ArrayList<User> userlist = udao.generateUserListKey(n, syspara);
            System.out.println("userlist:" + userlist.size());


            System.out.println("------密钥生成矩阵 begin------");

            Element[][] metrix = udao.keyGenerationMatrix(n, syspara, theta, userlist);
            for (int j = 0; j < n; j++) {

                for (int k = 0; k <= n; k++) {
                    System.out.println("j:" + j + " k:" + k);
                    System.out.println(metrix[j][k]);
                }

                //-------存信息---------
                JSONArray metrixArray = new JSONArray();
                for (Element[] row : metrix) {
                    for (Element ele : row) {

                        if (ele != null && !ele.equals("[]")) {
                            metrixArray.add(elementToString(ele));
                        }
                    }
                }
                object.put("mx", metrixArray);
                System.out.println("-------------");
            }

            System.out.println("------密钥生成矩阵 end------");
            List<Object> keyList = Lists.newArrayList();
            for (int num = 0; num < n; num++) {
                User u = userlist.get(num);
                udao.groupEncryptionKeyGeneration(u, metrix, syspara, userlist, theta);
                System.out.println("用户生成的加密群组公钥（R，O）如下：");
                System.out.println("u的群组加密密钥-R：" + u.getGroupEncryptionKey_R());
                System.out.println("u的群组加密密钥-O：" + u.getGroupEncryptionKey_O());
                System.out.println("u的群组解密密钥：" + elementToString(u.getGroupDecryptionKey()));


                //-------存信息---------
                System.out.println("-----++++++++++++++++++++++++++++++++++++---");

                JSONArray userArray = new JSONArray();
                for (int a = 0, x = userlist.size(); a < x; a++) {
                    User user = userlist.get(a);
                    JSONObject obj = new JSONObject();

                    obj.put("upk_1", elementToString(user.getUpk_1()));
                    obj.put("upk_2", elementToString(user.getUpk_2()));
                    obj.put("i", String.valueOf(user.getI()));
                    userArray.add(obj);
                }
                System.out.println(userArray);
                object.put("user_pki_list", userArray);
                object.put("n", n);
                Element pub = syspara.getP_pub();
                object.put("p_pub", elementToString(pub));
                Element k = syspara.getZ_q().newRandomElement().getImmutable();
                object.put("k", elementToString(k));
                Element cc1 = syspara.getP().mulZn(k).getImmutable();
                object.put("c1", elementToString(cc1));
                Element cc2 = u.getGroupEncryptionKey_R().mulZn(k).getImmutable();
                object.put("c2", elementToString(cc2));
                Element t_omegaa = u.getGroupEncryptionKey_O().powZn(k).getImmutable();
                object.put("t_omega", elementToString(t_omegaa));
                Element o = u.getGroupEncryptionKey_O();
                object.put("gek_o", elementToString(o));
                Element r = u.getGroupEncryptionKey_R();
                object.put("gek_r", elementToString(r));


                JSONObject gdktobj = new JSONObject();
                Element tt = u.getT().invert().duplicate();
                Element f = u.getGroupDecryptionKey();

                gdktobj.put("gek_key", elementToString(f));
                gdktobj.put("t", elementToString(tt));
                keyList.add(gdktobj);

            }
            object.put("gek_key_t", keyList);
            return object.toJSONString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @RequestMapping("gro/enc")
    @ResponseBody
    public JSONObject enc(
            @RequestBody Map<String, Object> encmsg) {
        try {
            System.out.println("------加密消息 begin------");
            UserDAO udao = new UserDAO();
            JSONObject object = new JSONObject();
            String cc = String.valueOf(encmsg.get("msg"));
            String c1 = String.valueOf(encmsg.get("c1"));
            String c2 = String.valueOf(encmsg.get("c2"));
            String t_omega = String.valueOf(encmsg.get("t_omega"));
            byte[] encrpt2 = Base64.encodeBase64(cc.getBytes(StandardCharsets.UTF_8));

            Pairing pairing = PairingFactory.getPairing("a.properties");
            Element C11 = StringToElement(c1, pairing);
            Element C22 = StringToElement(c2, pairing);
            Element tomegaa = StringToElement(t_omega, pairing);

            System.out.println("加密的消息：" + cc);
            Ciphertext c = udao.encryptMessage(C11, C22, tomegaa, encrpt2);

            byte[] c3 = c.getC3();
            object.put("c3", Base64.encodeBase64String(c3));
            object.put("c1", elementToString(c.getC1()));
            object.put("c2", elementToString(c.getC2()));
            object.put("message", JSON.toJSON(cc.getBytes()).toString());
            System.out.println("------加密消息 end------");

            return object;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    @RequestMapping("gro/dec")
    @ResponseBody
    JSONObject dec(@RequestBody Map<String, Object> decmsg) {
        try {
            System.out.println("------解密消息 begin------");
            UserDAO udao = new UserDAO();

            String msg = String.valueOf(decmsg.get("c3"));
            String C11 = String.valueOf(decmsg.get("c1"));
            String C22 = String.valueOf(decmsg.get("c2"));
            String SKey = String.valueOf(decmsg.get("SKey"));
            String t = String.valueOf(decmsg.get("t"));
            Pairing pairing = PairingFactory.getPairing("a.properties");

            byte[] C333 = Base64.decodeBase64(msg.getBytes());
            Element C111 = StringToElement(C11, pairing);
            Element C222 = StringToElement(C22, pairing);
            Element T = StringToElement(t, pairing);
            Element SSKey = StringToElement(SKey, pairing);

            byte[] dmge = udao.decryptMessage(C111, C222, T, SSKey, C333);
            String ddmge = new String(dmge, "UTF-8");
            String decodetxt = new String(Base64.decodeBase64(ddmge));
            for (int m = 0; m < dmge.length; m++) {
                System.out.print(dmge[m]);
            }
            JSONObject dmsg = new JSONObject();
            dmsg.put("decodetxt", decodetxt);
            System.out.println("dmessagString:" + ddmge);
            System.out.println("------解密消息 end------");
            System.out.print("test end");
            return dmsg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 类型转换 Element to STRING
     *
     * @param sig
     * @return
     */
    public static String elementToString(Element sig) {
        return Base64.encodeBase64String(sig.toBytes());
    }

    /**
     * 类型转换 String to Element
     *
     * @param s
     * @param pairing
     * @return
     */
    public static Element StringToElement(String s, Pairing pairing) {
        byte[] decodesig = Base64.decodeBase64(s.getBytes());
        Element ele = pairing.getG1().newElementFromBytes(decodesig);
        return ele;
    }

}















