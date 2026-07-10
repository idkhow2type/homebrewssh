from typing import cast, Protocol


class Named(Protocol):
    __name__: str


class Registry[T: Named, U: Named, K]:
    def __init__(self):
        self._objs: dict[str, U] = {}

    def register(self, attrs: K):
        def decorator(obj: T) -> U:
            for k, v in attrs.__dict__.items():
                setattr(obj, k, v)
            new_obj = cast(U, obj)
            self._objs[new_obj.__name__] = new_obj
            return new_obj

        return decorator
    
    def keys(self):
        return self._objs.keys()

    def values(self):
        return self._objs.values()

    def __getattr__(self, name):
        return self._objs[name]

    def __getitem__(self, key):
        return self._objs[key]


__all__ = ["Registry"]
