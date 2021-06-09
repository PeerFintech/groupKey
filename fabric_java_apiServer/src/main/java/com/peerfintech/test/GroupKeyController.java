package com.peerfintech.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.app.bean.FBInvokeRes;
import com.app.config.Config;
import com.app.util.FBUtil;
import com.peerfintech.dao.SysParametersDAO;
import com.peerfintech.dao.UserDAO;
import com.peerfintech.entity.Ciphertext;
import com.peerfintech.entity.SysParameters;
import com.peerfintech.entity.User;
import it.unisa.dia.gas.jpbc.Element;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class GroupKeyController {
    @RequestMapping("gro/add")
    @ResponseBody
    String invoke(@RequestParam(name = "n") int n,
                  @RequestBody Map<String,Object> ccc)
    {
        try {
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
            byte[] theta = {0, 1, 1, 0};//替换会话状态信息为固定值 2021-1-28 sxy added

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
                           metrixArray.add(ele.toString());
                        }
                    }
                }
                object.put("mx",metrixArray);
                System.out.println("-------------");
            }

            System.out.println("------密钥生成矩阵 end------");
            User u = userlist.get(0);

            udao.groupEncryptionKeyGeneration(u, metrix, syspara, userlist, theta);
            System.out.println("用户生成的加密群组公钥（R，O）如下：");
            System.out.println("R：" + u.getGroupEncryptionKey_R());
            System.out.println("O：" + u.getGroupEncryptionKey_O());
            System.out.println("自己的解密群组密钥：" + u.getGroupDecryptionKey());


            System.out.println("------加密消息 begin------");
            String cc =ccc.toString();
            //String cc = getRandomString(32);
            System.out.println("加密的消息：" + cc);
            Ciphertext c = udao.encryptMessage(syspara, u, cc.getBytes());

            System.out.println("------加密消息 end------");

            System.out.println("------解密消息 begin------");


            byte[] d = udao.decryptMessage(syspara, u, c);
            for (int m = 0; m < d.length; m++) {
                System.out.print(d[m]);
            }
            System.out.println();
            String dmessage = new String(d, "UTF-8");
            System.out.println("dmessage:" + dmessage);
            System.out.println("------解密消息 end------");


            System.out.print("test end");

            //-------存信息---------
            System.out.println("-----++++++++++++++++++++++++++++++++++++---");

            JSONArray userArray = new JSONArray();
            for (int a = 0, x = userlist.size(); a < x; a++) {
                User user = userlist.get(a);
                JSONObject obj = new JSONObject();

                obj.put("upk_1", user.getUpk_1().toString());
                obj.put("upk_2", user.getUpk_2().toString());
                obj.put("i", String.valueOf(user.getI()));
                //obj.put("Id", Arrays.toString(user.getId()));
                userArray.add(obj);
            }
            System.out.println(userArray);
            System.out.println("-----++++++++++++++++++++++++++++++++++++---");
            object.put("user_pki_list", userArray);


            //存信息
           // object.put("pai",syspara.getPairing().toString());

            object.put("p_pub", syspara.getP_pub().toString());
            object.put("gek_r", u.getGroupEncryptionKey_R().toString());
            object.put("gek_o", u.getGroupEncryptionKey_O().toString());
            object.put("t_omega",u.getGroupEncryptionKey_O().powZn(syspara.getZ_q().newRandomElement().getImmutable()).getImmutable().toString());
            object.put("c1", c.getC1().toString());
            object.put("c3", JSON.toJSON(c.getC3()).toString());
            object.put("c2", c.getC2().toString());
            object.put("message", JSON.toJSON(cc.getBytes()).toString());


            String arg = object.toJSONString();
            System.out.println("++++++++++++++++");
            System.out.println(arg);
            System.out.println("++++++++++++++++");


            FBInvokeRes res = FBUtil.fb.invoke(Config.CHANNEL_NAME, "mycc", "invoke", new String[]{arg});
            System.out.println("invoke结果" + res);
            return "invoke结果" + res.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "success";
    }



    public static String getRandomString(int length) {
        String str = "zxcvbnmlkjhgfdsaqwertyuiopQWERTYUIOPASDFGHJKLZXCVBNM1234567890";
        Random random = new Random();

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; ++i) {
            int number = random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }



    @RequestMapping("group/query")
    @ResponseBody
    String query(@RequestParam(name = "args") String args) {
        try {
            String res = FBUtil.fb.query(Config.CHANNEL_NAME, "mycc", "query", new String[]{args});
            System.out.println("query结果" + res);
            return "query结果" + res;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "success";
    }
}















