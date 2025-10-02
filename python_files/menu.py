from .menu_text import inner_help_dict

class MenuEntry:
	def __init__(self, command, function):
		self.command = command
		self.function = function
		self.inner_help = inner_help_dict.get(command)


