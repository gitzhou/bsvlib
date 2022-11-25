from bsvlib import Wallet
from bsvlib.constants import Chain

w = Wallet(chain=Chain.TEST)

w.add_key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
w.add_key('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')
print(w.get_balance(refresh=True))

outputs = [('mqBuyzdHfD87VfgxaYeM9pex3sJn4ihYHY', 724), ('mr1FHq6GwWzmD1y8Jxq6rNDGsiiQ9caF7r', 996)]
pushdatas = ['hello', b'world']
print(w.create_transaction(outputs=outputs, pushdatas=pushdatas, combine=True).broadcast())
