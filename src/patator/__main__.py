
if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()

    from .patator import cli
    cli()