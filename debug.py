from pympler import asizeof

def memsize(input_obj):
    return asizeof.asizeof(input_obj)
