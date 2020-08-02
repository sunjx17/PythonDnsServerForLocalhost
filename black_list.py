class black_list:
	def __init__(self):
		self.black_funcs=[]
	def add_func(self,func):
		self.black_funcs.append(func)
	def check_host(self,host):
		if len(self.black_funcs)>0:
			for i in range(len(self.black_funcs)):
				if self.black_funcs[i](host):
					return True
		return False
