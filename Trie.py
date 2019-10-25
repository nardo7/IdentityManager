import json
class Trie:
	def __init__(self,val):
		self.arr =[None,None,None,None,None,None,None,None,None,None]
		self.val = val

	def insert(self,ID):
		return self.__insert__(ID,0,False)

	def __insert__(self,ID,cont,flag):
		if cont==len(ID):
			#print(self)
			return flag
		if self.arr[int(ID[cont])] == None:
			self.arr[int(ID[cont])] = Trie(int(ID[cont]))
			flag = True
		return self.arr[int(ID[cont])].__insert__(ID,cont+1,flag)

	def contains(self,ID):
		return self._contains_(ID,0)

	def _contains_(self,ID,cont):
		if cont==len(ID):
			return True
		if self.arr[int(ID[cont])] == None:
			return False
		return self.arr[int(ID[cont])]._contains_(ID,cont+1)

	def __str__(self):
		return str(self.val)+self.arr.__str__()

t = Trie('$')
