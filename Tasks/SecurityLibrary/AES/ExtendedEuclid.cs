using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        /// 
        public int GetMultiplicativeInverse(int Number, int baseN)
        {
            int Q, A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = Number;
            int _Q, _A1, _A2, _A3, _B1, _B2, _B3;
            while (true)
            {
                if (B3 == 1)
                    break;
                if (B3 == 0)
                    return -1;
                _Q = A3 / B3;
                _A1 = B1;
                _A2 = B2;
                _A3 = B3;
                _B1 = A1 - (_Q * B1);
                _B2 = A2 - (_Q * B2);
                _B3 = A3 % B3;
                Q = _Q;
                A1 = _A1;
                A2 = _A2;
                A3 = _A3;
                B1 = _B1;
                B2 = _B2;
                B3 = _B3;

            }
            while (B2 < 0)
                B2 += baseN;

            if (B2 >= baseN)
                B2 = B2 % baseN;
            return B2;
        } 
    }
}
