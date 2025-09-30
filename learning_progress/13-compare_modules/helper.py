user_view = set()
with open ("/proc/modules") as f:
	for line in f:
		line = line.strip()
		if not line:
			continue
		parts = line.split()
		mod_name = parts[0]
		user_view.add(mod_name)
		
kern_view = set()
with open ("/proc/loaded_mods") as f:
	for line in f:
		line = line.strip()
		if not line:	
			continue
		part = line.split()
		mod_name = part[0]
		kern_view.add(mod_name)
		
hidden_mods = kern_view - user_view

if(hidden_mods):
	print("Hidden modules are:\n")
	for i in sorted(hidden_mods):
		print(i);
else:
	print("No hidden modules were detected\nExiting")
	
