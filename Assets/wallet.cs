using UnityEngine;

using UnityEngine.UI;
using System.Security.Cryptography;
using System.Collections;
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

using Org.BouncyCastle.Crypto.Utilities;
using System.Linq;
[Serializable]
public class Param_createTranscation
{
    public int version;
    public int nonce;
    public string to;
    public int amount;
    public string pubKey;
    public int gasPrice;
    public int gasLimit;
    public string code = "";
    public string data = "";
    public string signature;
    
   

}

[Serializable]
public class Param_GetDsBlock
{

}

[Serializable]
public class CreatTranscation
{
    public int id;
    public string jsonrpc;
    public string method;
    public List<Param_createTranscation>  paramsList;
}

[Serializable]
public class GetDsBlock
{
    public int id;
    public string jsonrpc;
    public string method;
    public List<string> paramsList;
}


public class wallet : MonoBehaviour
{

    string prv = "FDC4372E786FDBC8BA5396FA4ABAC81E69AD9EA404A8C37877AB008A0198A733";
    string pub =    "02B23C49E90EFC0C01397BD9624DD54B40F64BF49CA5E8C8B759BF26B4DF11A9EA";
    string prvTmp = "C7A5FCF7B927D652231C56CB8F007D2E4A392726620D6604B50F54BC32732A16";
    string pubTmp = "024F39C9B8DC1355E806F5C324A8D80B67FD0B1848A2A78F7C7E9E514ED9C51074";

    string addrDest = "B21A114A3CAB1499F9548EE16939A5C578B6A748";
    private DerObjectIdentifier publicKeyParamSet;
    private SecureRandom random = new SecureRandom();
   

    private static readonly Org.BouncyCastle.Asn1.X9.X9ECParameters curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
    private static readonly Org.BouncyCastle.Crypto.Parameters.ECDomainParameters domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

   
    public BigInteger GenerateRandom()
    {
         
        BigInteger d;
        int minWeight = curve.N.BitLength >> 2;

        for (; ; )
        {
            d = new BigInteger(curve.N.BitLength, random);

            if (d.CompareTo(BigInteger.Two) < 0 || d.CompareTo(curve.N) >= 0)
                continue;

            if (WNafUtilities.GetNafWeight(d) < minWeight)
                continue;

            break;
        }

        return d;
    }

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
    public string GetSign(byte[] msg)
    {
        //Org.BouncyCastle.Math.BigInteger d = new Org.BouncyCastle.Math.BigInteger(Convert.FromBase64String(privKey));
        byte[] prvB = StringToByteArray(prv);
        byte[] pubB = StringToByteArray(pub);
        //byte[] prvB = StringToByteArray(prvTmp);
        //byte[] pubB = StringToByteArray(pubTmp);
        Org.BouncyCastle.Math.BigInteger sk = new Org.BouncyCastle.Math.BigInteger(+1,prvB);
        Org.BouncyCastle.Math.EC.ECPoint q = domain.G.Multiply(sk);

        byte[] pubKeyX = q.Normalize().AffineXCoord.GetEncoded();
        byte[] pubKeyY = q.Normalize().AffineYCoord.GetEncoded();
        BigInteger k = GenerateRandom();
        //BigInteger k = new BigInteger(+1,StringToByteArray("015B931D9C7BF3A7A70E57868BF29712377E74355FC59032CD7547C80E179010"));
        //Debug.Log("kv:" + BitConverter.ToString(kv.ToByteArray()).Replace("-", ""));
        Debug.Log("K:" + BitConverter.ToString(k.ToByteArray()).Replace("-", ""));
        ECPoint Q = domain.G.Multiply(k);
        Org.BouncyCastle.Crypto.Digests.Sha256Digest digester = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        byte[] h = new byte[digester.GetDigestSize()];
        
        digester.BlockUpdate(Q.GetEncoded(true), 0, Q.GetEncoded(true).Length);
        digester.BlockUpdate(pubB, 0, pubB.Length);
        digester.BlockUpdate(msg, 0, msg.Length);

        digester.DoFinal(h, 0);
        
        Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(+1,h);
        
        BigInteger s = r.Multiply(sk);
        s = k.Subtract(s);
        s = s.Mod(domain.n);
        string rt = BitConverter.ToString(r.ToByteArray()).Replace("-", "");
        if (rt.Length > 32)
            rt = rt.Remove(0, 2);
        string st = BitConverter.ToString(s.ToByteArray()).Replace("-", "");
        return rt + st;
        

    }
   
    void Start()
    {
        gameObject.GetComponent<Button>().onClick.AddListener(TaskOnClick);
         
    }

    IEnumerator WaitForWWW(WWW www)
    {
        yield return www;
        string txt = "";
        if (string.IsNullOrEmpty(www.error))
            txt = www.text;  //text of success
        else
            txt = www.error;  //error
        GameObject.Find("Text").GetComponent<Text>().text = "++++++\n\n" + txt;
        Debug.Log(txt);
    }
    string fillpad(string st,int fill)
    {
        string str = st;
        for (int i = 0; i < fill -st.Length; i++)
            str = "0" + str;
        Debug.Log(str.Length);
        return str;
    }
    void TaskOnClick()
    {
        try
        {
            GameObject.Find("Text").GetComponent<Text>().text = "starting..";
            CreatTranscation creatTransIns = new CreatTranscation();

            Param_createTranscation ParamListIns = new Param_createTranscation();
            ParamListIns.amount = 83;
            ParamListIns.version = 0;
            ParamListIns.nonce = 5;
            ParamListIns.to = addrDest.ToLower();
            ParamListIns.pubKey = pub.ToLower();
            ParamListIns.gasLimit = 1;
            ParamListIns.gasPrice = 1;
            

            string codeHex = BitConverter.ToString(StringToByteArray(ParamListIns.code)).Replace("-", "");
            string dataHex = BitConverter.ToString(StringToByteArray(ParamListIns.data)).Replace("-", "");
            string version = BitConverter.ToString(BitConverter.GetBytes(ParamListIns.version)).Replace("-", "");

            string nonce = BitConverter.ToString(BitConverter.GetBytes(ParamListIns.nonce)).Replace("-", "");
            string amount = BitConverter.ToString(StringToByteArray(ParamListIns.amount.ToString())).Replace("-", "");
            string gasPrice = BitConverter.ToString(BitConverter.GetBytes(ParamListIns.gasPrice)).Replace("-", "");
            string gasLimit = BitConverter.ToString(BitConverter.GetBytes(ParamListIns.gasLimit)).Replace("-", "");
            string codeLength = fillpad(ParamListIns.code.Length.ToString(), 8);
            string dataLength = fillpad(ParamListIns.data.Length.ToString(), 8);
            version = fillpad(version, 64);
            nonce = fillpad(nonce, 64);
            amount = fillpad(amount, 64);
            gasPrice = fillpad(gasPrice, 64);
            gasLimit = fillpad(gasLimit, 64);

            string signPrepare = version  + nonce  + ParamListIns.to + ParamListIns.pubKey + amount + gasPrice  + gasLimit + codeLength  + codeHex + dataLength  + dataHex;
            Debug.Log("signPrepare:" + signPrepare);
            string sign = GetSign(StringToByteArray(signPrepare));
            Debug.Log(sign);
            ParamListIns.signature =  sign.ToLower();

            creatTransIns.id = 1;
            creatTransIns.jsonrpc = "2.0";
            creatTransIns.method = "CreateTransaction";
            creatTransIns.paramsList = new List<Param_createTranscation>();
            creatTransIns.paramsList.Add(ParamListIns);
            string json = JsonUtility.ToJson(creatTransIns);


            string tmp = "EF9237CE5B615BC08677EE5ABFBD85F73F7F8868CB1B5FBA4C1309F16061AA133821FBE2A758D2BBE6AA040A940D41B7D3B869CEE945150AA4A40E6FF719EEC24B2681CD5CE06B50273436584066046656D5EFED73157591";
           
            //GetSign(System.Text.Encoding.ASCII.GetBytes(json.ToCharArray()));

            json = json.Replace("paramsList", "params");
            Debug.Log(json);

            /*
            GetDsBlock getDsBlockIns = new GetDsBlock();
            getDsBlockIns.id = 1;
            getDsBlockIns.jsonrpc = "2.0";
            getDsBlockIns.method = "GetDsBlock";
            getDsBlockIns.paramsList = new List<string>();
            getDsBlockIns.paramsList.Add("1");
            json = JsonUtility.ToJson(getDsBlockIns);
            json = json.Replace("paramsList", "params");
            Debug.Log(json);
            */


            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers.Add("Content-Type", "application/json");
            //byte[] b = System.Text.Encoding.UTF8.GetBytes();
            byte[] pData = System.Text.Encoding.ASCII.GetBytes(json.ToCharArray());
             
            WWW api = new WWW("https://api-scilla.zilliqa.com/", pData, headers);
          
            StartCoroutine(WaitForWWW(api));
        }
        catch (UnityException ex) { Debug.Log(ex.Message); }
    }

}
