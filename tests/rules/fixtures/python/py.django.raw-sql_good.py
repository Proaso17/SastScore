def query(model, pk):
    return model.objects.filter(id=pk)
