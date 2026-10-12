import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { SignalRecordingService } from "../application/signals/SignalRecordingService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { logToolExecution } from "./toolLogging.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named signal recording contract to shared validation and session Evidence recording. */
export const registerSignalTools = (
  server: EvidenceMcpServer,
  service: SignalRecordingService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("decode_signal_recording");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        withAdmittedAnalysis,
        contract.name,
        context.mcpReq.signal,
        async () => {
          const result = await logToolExecution(logger, contract.name, () =>
            service.decode(input, { signal: context.mcpReq.signal }),
          );
          if (!result.ok) {
            const partial = result.error.partialObservation;
            if (
              partial !== undefined &&
              "evidence_id" in partial &&
              typeof partial.evidence_id === "string"
            ) {
              const recorded = recordEvidence?.(partial);
              if (recorded !== undefined)
                return server.delivery.toRecordedPartialErrorToolResult(
                  result.error,
                  partial.evidence_id,
                  recorded,
                );
            }
            return server.delivery.toCallToolResult(result, contract);
          }
          return server.delivery.toEvidenceToolResult(
            result.value,
            contract,
            recordEvidence?.(result.value),
          );
        },
      ),
  );
};
