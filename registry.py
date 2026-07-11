from typing import cast, Protocol, Any


class _Named(Protocol):
    __name__: str


class Registry[T: _Named, U: _Named, K]:
    def __init__(self):
        self._objs: dict[str, U] = {}
        self._meta: dict[str, dict[str, Any]] = {}

    def register(self, attrs: K):
        def decorator(obj: T) -> U:
            meta = {}
            for k, v in attrs.__dict__.items():
                setattr(obj, k, v)
                meta[k] = v
            new_obj = cast(U, obj)
            self._objs[new_obj.__name__] = new_obj
            self._meta[new_obj.__name__] = meta
            return new_obj

        return decorator

    def __getattr__(self, name):
        return self._objs[name]

    def __getitem__(self, key):
        return {meta[key]: self._objs[name] for name, meta in self._meta.items()}


__all__ = ["Registry"]
