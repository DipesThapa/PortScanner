import dill
import joblib
import numpy
import numpy as np
import pandas
import pandas as pd
import torch


def true_positives(path, url, data):
    # ruleid: ml-unsafe-model-deserialization
    torch.load(path)

    # ruleid: ml-unsafe-model-deserialization
    torch.load(path, map_location="cpu")

    # ruleid: ml-unsafe-model-deserialization
    joblib.load(path)

    # ruleid: ml-unsafe-model-deserialization
    numpy.load(path, allow_pickle=True)

    # ruleid: ml-unsafe-model-deserialization
    np.load(path, allow_pickle=True)

    # ruleid: ml-unsafe-model-deserialization
    pandas.read_pickle(url)

    # ruleid: ml-unsafe-model-deserialization
    pd.read_pickle(path)

    # ruleid: ml-unsafe-model-deserialization
    dill.loads(data)


def true_negatives(path, data):
    # ok: ml-unsafe-model-deserialization
    torch.load(path, weights_only=True)

    # ok: ml-unsafe-model-deserialization
    numpy.load(path)

    # ok: ml-unsafe-model-deserialization
    np.load(path, allow_pickle=False)

    # ok: ml-unsafe-model-deserialization
    import json
    json.loads(data)
