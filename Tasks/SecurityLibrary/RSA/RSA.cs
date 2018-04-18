using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
           int n = p*q ;
           int result = M;
           for (int i = 1; i < e; i++)
           {
               result =(int) ((result % n) * (M % n)) % n; 
           }
           return result;
           // throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            ExtendedEuclid EX = new ExtendedEuclid();
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int extendedNumber = EX.GetMultiplicativeInverse(e,Qn);

            int d = extendedNumber % Qn;
            int result = C;
            for (int i = 1; i < d; i++)
            {
                result = (int)((result % n) * (C % n)) % n;
            }
            return result;
           // throw new NotImplementedException();
        }
    }
}
