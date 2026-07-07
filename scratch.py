class A:
    pass


class C(A):
    pass


class B:
    @classmethod
    def f[T](cls, x: type[T])->T:
        return x()


inst = B.f(C)
