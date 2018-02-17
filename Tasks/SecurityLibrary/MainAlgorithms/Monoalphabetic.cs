using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
         Dictionary<char, char> alphapets = new Dictionary<char, char>();
        
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
             cipherText = cipherText.ToLower();
             key = key.ToLower();
             alphapets.Add(key[0],'a'); alphapets.Add(key[12],'m');
             alphapets.Add(key[1],'b'); alphapets.Add(key[13],'n');
             alphapets.Add(key[2],'c'); alphapets.Add(key[14],'o');
             alphapets.Add(key[3],'d'); alphapets.Add(key[15],'p');
             alphapets.Add(key[4],'e'); alphapets.Add(key[16],'q');
             alphapets.Add(key[5],'f'); alphapets.Add(key[17],'r');
             alphapets.Add(key[6],'g'); alphapets.Add(key[18],'s');
             alphapets.Add(key[7],'h'); alphapets.Add(key[19],'t');
             alphapets.Add(key[8],'i'); alphapets.Add(key[20],'u');
             alphapets.Add(key[9],'j'); alphapets.Add(key[21],'v');
             alphapets.Add(key[10],'k'); alphapets.Add(key[22],'w');
             alphapets.Add(key[11],'l'); alphapets.Add(key[23],'x');
             alphapets.Add(key[24],'y'); alphapets.Add(key[25],'z');
             string plainText = "";
             for (int i = 0; i < cipherText.Length; i++)
                  plainText = plainText + alphapets[cipherText[i]];

             return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
             plainText = plainText.ToLower();
             key = key.ToLower();
             alphapets.Add('a', key[0]); alphapets.Add('m', key[12]);
             alphapets.Add('b', key[1]); alphapets.Add('n', key[13]);
             alphapets.Add('c', key[2]); alphapets.Add('o', key[14]);
             alphapets.Add('d', key[3]); alphapets.Add('p', key[15]);
             alphapets.Add('e', key[4]); alphapets.Add('q', key[16]);
             alphapets.Add('f', key[5]); alphapets.Add('r', key[17]);
             alphapets.Add('g', key[6]); alphapets.Add('s', key[18]);
             alphapets.Add('h', key[7]); alphapets.Add('t', key[19]);
             alphapets.Add('i', key[8]); alphapets.Add('u', key[20]);
             alphapets.Add('j', key[9]); alphapets.Add('v', key[21]);
             alphapets.Add('k', key[10]); alphapets.Add('w', key[22]);
             alphapets.Add('l', key[11]); alphapets.Add('x', key[23]);
             alphapets.Add('y', key[24]); alphapets.Add('z', key[25]);
             string cipherText = "";
             for(int i=0 ; i<plainText.Length ; i++)
                  cipherText = cipherText + alphapets[plainText[i]];
             
             return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
             cipher = cipher.ToLower();
             int[] count = new int[123];
             char[] alphapets = new char[] {'e','t','a','o','i','n','s','r','h','l','d','c','u','m','f','p','g','w','y','b','v','k','x','j','q','z'};
             Array.Clear(count, 0, count.Length);

             for(int i=0 ; i <cipher.Length ; i++)
                  count[(int)cipher[i]]++;

             for (int i = 0; i < 26; i++)
             {
                  int maxIndex = Array.IndexOf(count, count.Max());
                  cipher = cipher.Replace((char)maxIndex, alphapets[i]);
                  count[maxIndex] = 0;
             }


               return cipher;
        }


    }
}
