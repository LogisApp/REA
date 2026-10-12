import * as t from "@babel/types";
import { semanticStaticPropertyKey } from "./javascriptAstValues.js";

/** Read only explicit type-reference attributes; never evaluate an options expression. */
export const typescriptImportResolutionMode = (
  node: t.Node,
): "import" | "require" | undefined => {
  if (t.isTSImportType(node)) {
    const attributes = literalProperty(node.options, "with");
    const mode = literalProperty(attributes, "resolution-mode");
    return t.isStringLiteral(mode) &&
      (mode.value === "import" || mode.value === "require")
      ? mode.value
      : undefined;
  }
  if (
    !t.isImportDeclaration(node) &&
    !t.isExportNamedDeclaration(node) &&
    !t.isExportAllDeclaration(node)
  )
    return undefined;
  const kind = t.isImportDeclaration(node) ? node.importKind : node.exportKind;
  if (kind !== "type") return undefined;
  const mode = node.attributes?.find(
    ({ key }) =>
      (t.isStringLiteral(key) ? key.value : key.name) === "resolution-mode",
  )?.value.value;
  return mode === "import" || mode === "require" ? mode : undefined;
};

const literalProperty = (
  node: t.Node | null | undefined,
  key: string,
): t.Node | undefined =>
  t.isObjectExpression(node)
    ? node.properties.find(
        (property): property is t.ObjectProperty =>
          t.isObjectProperty(property) &&
          semanticStaticPropertyKey(property.key, property.computed) === key,
      )?.value
    : undefined;

/** Retain a statically declared inline type qualifier without looking up runtime values. */
export const typescriptImportTypeName = (
  node: t.TSImportType,
): string | null => {
  const names: string[] = [];
  let qualifier = node.qualifier;
  while (t.isTSQualifiedName(qualifier)) {
    names.unshift(qualifier.right.name);
    qualifier = qualifier.left;
  }
  if (t.isIdentifier(qualifier)) names.unshift(qualifier.name);
  return names.length === 0 ? null : names.join(".");
};
