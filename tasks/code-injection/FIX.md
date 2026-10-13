# FIX — Code Injection
Root cause: калькулятор вызывает eval(expression), хотя продукту нужна только арифметика.
В учебной версии eval выполняется непосредственно в Flask handler, без отдельного worker и timeout.
Container resource limits не являются sandbox для языка.
Демонстрация не содержит blacklist или самостоятельной задачи обхода sandbox.

Уязвимый участок:
~~~python
answer = eval(expression)
~~~

Безопасный ограниченный evaluator:
~~~python
# safe-example
import ast
import math
import operator

def safe_calculate(expression):
    if not isinstance(expression, str) or not 1 <= len(expression) <= 256:
        raise ValueError("Invalid expression")
    tree = ast.parse(expression, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 80:
        raise ValueError("Too many nodes")
    operations = {ast.Add: operator.add, ast.Sub: operator.sub,
                  ast.Mult: operator.mul, ast.Div: operator.truediv}
    def visit(node, depth=0):
        if depth > 16:
            raise ValueError("Too deep")
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            result = node.value
            if abs(result) > 1e9:
                raise ValueError("Number too large")
        elif isinstance(node, ast.UnaryOp) and type(node.op) in (ast.UAdd, ast.USub):
            operand = visit(node.operand, depth+1)
            result = operand if isinstance(node.op, ast.UAdd) else -operand
        elif isinstance(node, ast.BinOp) and type(node.op) in operations:
            result = operations[type(node.op)](visit(node.left, depth+1), visit(node.right, depth+1))
        else:
            raise ValueError("Unsupported expression")
        if abs(result) > 1e12 or (isinstance(result, float) and not math.isfinite(result)):
            raise ValueError("Result outside limits")
        return result
    return visit(tree.body)
~~~

Разрешены numbers, скобки, unary +/- и + - * /. Остальные AST nodes не выполняются.
Нет вызова eval/exec в безопасном варианте. Ошибки syntax, bounds и division by zero
должны преобразовываться приложением в понятный отказ.
Это ограниченная грамматика; blacklist и скрытие отдельных имён не заменяют её.
