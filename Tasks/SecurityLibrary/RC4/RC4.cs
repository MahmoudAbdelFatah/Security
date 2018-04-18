using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
    List<int> initialStateList = new List<int>(256) ;
    List<int> temporaryList = new List<int>(256) ;
    List<int> perumtedStateList = new List<int>(256) ;
    List<int> keyStream; 


        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            keyStream = new List<int>(new int[cipherText.Length]);
            initialStateList = new List<int>(new int[256]);
            temporaryList = new List<int>(new int[256]);
            perumtedStateList = new List<int>(new int[256]);

            listIntialisation(key);
            copyListByValue(initialStateList, perumtedStateList);
            Key_Scheduling_Algorithm(initialStateList, temporaryList, perumtedStateList);
            Random_Genration_Algorithm(cipherText, perumtedStateList);
            return getCipherText(cipherText, keyStream);
        }

        public override  string Encrypt(string plainText, string key)
        {
            keyStream = new List<int>(new int [plainText.Length]);
            initialStateList = new List<int>(new int[256]);
            temporaryList = new List<int>(new int[256]);
            perumtedStateList = new List<int>(new int[256]);

            listIntialisation(key);
            copyListByValue(initialStateList, perumtedStateList);
            Key_Scheduling_Algorithm(initialStateList, temporaryList, perumtedStateList);
            Random_Genration_Algorithm(plainText, perumtedStateList);
            return getCipherText(plainText, keyStream);
          //  throw new NotImplementedException();
           
        }
        private void listIntialisation(string key)
        {
            int kLen = key.Length;
            for (int i = 0; i < 256; i++)
            {
                initialStateList[i] = i;
                temporaryList[i] = key[i % kLen]; 
            }
        }  
        private void copyListByValue (List<int> source , List<int> destenation){
            destenation.Clear();
            destenation.AddRange(source);
        }
          /// <summary>
          ///  j := 0
            //for i from 0 to 255
            //    j := (j + S[i] + key[i mod keylength]) mod 256
            //    swap values of S[i] and S[j]
            //endfor
          /// </summary>
          /// <param name="initialStateList"></param>
          /// <param name="temporaryList"></param>
          /// <param name="perumtedStateList"></param>
        private void Key_Scheduling_Algorithm(List<int> initialStateList, List<int> temporaryList, List<int> perumtedStateList)
        {
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + perumtedStateList[i] + temporaryList[i]) % 256;
                ///// Swap ///// 
                int temp = perumtedStateList[i];
                perumtedStateList[i] = perumtedStateList[j];
                perumtedStateList[j] = temp;
            }

        }
        /// <summary>
        /// i := 0
        //j := 0
        //while GeneratingOutput:
        //    i := (i + 1) mod 256
        //    j := (j + S[i]) mod 256
        //    swap values of S[i] and S[j]
        //    K := S[(S[i] + S[j]) mod 256]
        //    output K
        //endwhile
        /// </summary>
        /// <param name="initialStateList"></param>
        /// <param name="temporaryList"></param>
        /// <param name="perumtedStateList"></param>
        private void Random_Genration_Algorithm(string text, List<int> perumtedStateList)
        {
            int j = 0 , i = 0;
            int klen = text.Length;
            for (int iterator = 0; iterator < klen; iterator++ )
            {
                i = (i + 1) % 256;
                j = (j + perumtedStateList[i]) % 256;
                ///// Swap ///// 
                int temp = perumtedStateList[i];
                perumtedStateList[i] = perumtedStateList[j];
                perumtedStateList[j] = temp;

                keyStream[iterator]=perumtedStateList[(perumtedStateList[i]+perumtedStateList[j])%256];
             
            }
            
        }

        private string getCipherText(string plaintext, List<int> keyStream)
        {
            System.Text.StringBuilder strBuilder = new System.Text.StringBuilder(plaintext);

            for (int i = 0; i < plaintext.Length; i++)
            {
                int num = strBuilder[i];
                int num2 = keyStream[i];
                int result = num ^ num2;
                strBuilder[i] = (char)(result);
            }
            return strBuilder.ToString();
        }
      
    }
}
