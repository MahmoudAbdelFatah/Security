using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> Cs = new List<long>(new long[2]);
            int K = keyGenration(y, k, q);
            int C1 = keyGenration(alpha, k, q);
            int C2 = ((K % q) * (m % q)) % q;
            Cs[0] = C1;
            Cs[1] = C2; 

            return Cs; 
           // throw new NotImplementedException();
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {

            ExtendedEuclid EX = new ExtendedEuclid();
            int K = keyGenration(c1, x, q);
            int Kinverse = EX.GetMultiplicativeInverse(K, q) % q;
            int M = ((c2 % q) * (Kinverse % q)) % q;
            return M;
            //throw new NotImplementedException();

        }
        private int keyGenration(int alpha, int X, int q)
        {
            int result = alpha;
            for (int i = 1; i < X; i++)
            {
                result = (int)((result % q) * (alpha % q)) % q;
            }
            return result;
        }
    }
}
